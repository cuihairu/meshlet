//! 设备发布计划投影：过滤设备对象并复用发布计划层校验。

use crate::service::MeshState;
use meshlet_publish::{
    DnsPlan, HttpRoute, HttpRouteSet, PortForwardConfig, ProbeSchedule, PublishPlan,
};
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
