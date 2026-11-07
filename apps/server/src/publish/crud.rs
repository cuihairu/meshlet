//! 四类发布对象的领域规则与 staged 状态变更。

use super::auth::plan_error;
use super::models::{PublishDnsRecord, PublishForward, PublishHttpRoute, PublishProbe};
use super::views::{
    CreatePublishDnsRecordRequest, CreatePublishForwardRequest, CreatePublishHttpRouteRequest,
    CreatePublishProbeRequest, PublishDnsRecordView, PublishForwardView, PublishHttpRouteView,
    PublishProbeView,
};
use crate::service::{MeshState, ServiceError};
use meshlet_publish::health::ProbeTarget;
use meshlet_publish::{ForwardProtocol, HttpRoute, HttpRouteSet, PortForwardConfig, ProbeSchedule};

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

pub(crate) fn create_forward(
    state: &mut MeshState,
    network_id: &str,
    req: CreatePublishForwardRequest,
) -> Result<PublishForwardView, ServiceError> {
    state.network(network_id)?;
    super::auth::device_in_network(state, network_id, &req.device_id)?;
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
    let policy = super::auth::parse_policy(&req.allowed_source_cidrs, &req.allowed_bearer_tokens)?;
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
    let view = super::views::to_forward_view(state, network_id, &forward);
    state
        .publishes
        .entry(network_id.to_string())
        .or_default()
        .forwards
        .push(forward);
    crate::service::record_revision(state, network_id)?;
    Ok(view)
}

pub(crate) fn list_forwards(
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
                .map(|f| super::views::to_forward_view(state, network_id, f))
                .collect()
        })
        .unwrap_or_default())
}

pub(crate) fn get_forward(
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
    Ok(super::views::to_forward_view(state, network_id, forward))
}

/// 删除返回 `(forward_id)` 供落库与审计。
pub(crate) fn delete_forward(
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

pub(crate) fn create_http_route(
    state: &mut MeshState,
    network_id: &str,
    req: CreatePublishHttpRouteRequest,
) -> Result<PublishHttpRouteView, ServiceError> {
    state.network(network_id)?;
    super::auth::device_in_network(state, network_id, &req.device_id)?;
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
    let policy = super::auth::parse_policy(&req.allowed_source_cidrs, &req.allowed_bearer_tokens)?;
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
    let view = super::views::to_http_route_view(state, network_id, &route);
    state
        .publishes
        .entry(network_id.to_string())
        .or_default()
        .http_routes
        .push(route);
    crate::service::record_revision(state, network_id)?;
    Ok(view)
}

pub(crate) fn list_http_routes(
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
                .map(|r| super::views::to_http_route_view(state, network_id, r))
                .collect()
        })
        .unwrap_or_default())
}

pub(crate) fn get_http_route(
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
    Ok(super::views::to_http_route_view(state, network_id, route))
}

pub(crate) fn delete_http_route(
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

pub(crate) fn create_probe(
    state: &mut MeshState,
    network_id: &str,
    req: CreatePublishProbeRequest,
) -> Result<PublishProbeView, ServiceError> {
    state.network(network_id)?;
    super::auth::device_in_network(state, network_id, &req.device_id)?;
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
    let view = super::views::to_probe_view(state, network_id, &probe);
    state
        .publishes
        .entry(network_id.to_string())
        .or_default()
        .probes
        .push(probe);
    crate::service::record_revision(state, network_id)?;
    Ok(view)
}

pub(crate) fn list_probes(
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
                .map(|p| super::views::to_probe_view(state, network_id, p))
                .collect()
        })
        .unwrap_or_default())
}

pub(crate) fn get_probe(
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
    Ok(super::views::to_probe_view(state, network_id, probe))
}

pub(crate) fn delete_probe(
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
pub(crate) fn record_probe_health(
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

pub(crate) fn create_dns_record(
    state: &mut MeshState,
    network_id: &str,
    req: CreatePublishDnsRecordRequest,
) -> Result<PublishDnsRecordView, ServiceError> {
    state.network(network_id)?;
    super::auth::device_in_network(state, network_id, &req.device_id)?;
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
    let view = super::views::to_dns_record_view(state, network_id, &record);
    state
        .publishes
        .entry(network_id.to_string())
        .or_default()
        .dns_records
        .push(record);
    crate::service::record_revision(state, network_id)?;
    Ok(view)
}

pub(crate) fn list_dns_records(
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
                .map(|r| super::views::to_dns_record_view(state, network_id, r))
                .collect()
        })
        .unwrap_or_default())
}

pub(crate) fn get_dns_record(
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
    Ok(super::views::to_dns_record_view(state, network_id, record))
}

pub(crate) fn delete_dns_record(
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
