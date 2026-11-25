//! Domain rules and staged state changes for the four publish object types.

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

/// Port conflicts are judged per device: each device is its own host, so the same
/// `(protocol, listener address:port)` can be bound only once per device.
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

/// Deletion returns the `(forward_id)` for persistence and auditing.
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
// Domain functions for HTTP routes
// ---------------------------------------------------------------------------

/// `(hostname, path_prefix)` is unique within a network (case-insensitive), matching
/// the deduplication criteria of the plan-layer `HttpRouteSet`.
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

/// A device binds only one HTTP listening socket and uses only one termination mode:
/// the plan has just two slots, `http_listener` and `tls_passthrough`, and any other
/// values are silently dropped (a second listener is not bound; mixing in TLS routes
/// would flip the whole device into SNI sniffing).
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

/// TLS passthrough is SNI sniffing + raw byte pass-through: meshlet holds no
/// certificate and does not decrypt. The two capabilities below therefore simply do
/// not exist in this mode; silently ignoring them would be misrepresentation, so
/// creation returns 409 unconditionally (extending the same criterion as "mixed
/// termination mode is 409"):
/// - `allowed_bearer_tokens`: the router cannot see HTTP headers (TLS is opaque to
///   it), so tokens are never checked;
/// - `path_prefix` other than `/`: sniffing selects the route by SNI host name only
///   (always matching `/`), so a path prefix never takes part in matching.
///
/// To get these two capabilities, use a plain HTTP route; real TLS termination is
/// not currently supported, so it is refused outright rather than pretended.
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
// Domain functions for probes
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

/// Agent health report (in-memory side): only updates the `last_*` fields of probes belonging to that device.
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
// Domain functions for DNS records
// ---------------------------------------------------------------------------

/// Each device has at most one `(bind_address, internal_suffix)` socket: a new record
/// must agree with that device's existing records on the socket — this guarantees a
/// device yields only `Some(DnsPlan)` when plans are aggregated.
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
