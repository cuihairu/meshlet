//! Server plan adaptation.

use meshlet_network::DevicePlan;

/// hub 入口地址兜底（纯逻辑，§16.4）：服务端不知道 agent 的网络位置，计划里
/// hub peer 的 endpoint 为 `None`；agent 用本地 `[dataplane] hub_endpoint`
///（`host:port`）填充，设备才能主动发起握手。服务端已带值（未来通告
/// advertise endpoint）则尊重服务端，不覆盖；未配置兜底则原样返回。
pub(super) fn plan_with_hub_endpoint(plan: &DevicePlan, hub_endpoint: Option<&str>) -> DevicePlan {
    let mut local = plan.clone();
    if let (Some(endpoint), Some(peer)) = (hub_endpoint, local.tunnel.peers.first_mut()) {
        if peer.endpoint.is_none() {
            peer.endpoint = Some(match plan.hub_port {
                Some(port) => endpoint
                    .rsplit_once(':')
                    .map(|(host, _)| format!("{host}:{port}"))
                    .unwrap_or_else(|| format!("{endpoint}:{port}")),
                None => endpoint.to_string(),
            });
        }
    }
    local
}

/// SEL-003 hub 兜底：hub peer（隧道配置第一个 peer，即服务端计划的 hub）的
/// persistent-keepalive 强制 ≥ [meshlet_network::HUB_KEEPALIVE_SECS]，让 hub 永不
/// 掉（NAT 映射常开，直连回退后随时可回）。计划显式给更高值则尊重。
pub(super) fn enforce_hub_keepalive(plan: &mut DevicePlan) {
    if let Some(peer) = plan.tunnel.peers.first_mut() {
        let floor = meshlet_network::HUB_KEEPALIVE_SECS;
        if peer.persistent_keepalive_secs.unwrap_or(0) < floor {
            peer.persistent_keepalive_secs = Some(floor);
        }
    }
}
