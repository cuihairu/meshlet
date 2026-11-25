//! Server plan adaptation.

use meshlet_network::DevicePlan;

/// Hub entry-address fallback (pure logic, §16.4): the server does not know the
/// agent's network location, so the hub peer's endpoint in the plan is `None`; the
/// agent fills it from the local `[dataplane] hub_endpoint` (`host:port`) so the
/// device can initiate the handshake itself. A value already present (a future
/// advertised endpoint) is respected and never overwritten; with no fallback
/// configured the plan is returned unchanged.
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

/// SEL-003 hub fallback: the hub peer (the first peer in the tunnel config, i.e.
/// the server plan's hub) is forced to persistent-keepalive >= [meshlet_network::HUB_KEEPALIVE_SECS] so the hub never drops (the NAT mapping stays open, and the direct fallback can return to it at any time). An explicitly higher value in the plan is respected.
pub(super) fn enforce_hub_keepalive(plan: &mut DevicePlan) {
    if let Some(peer) = plan.tunnel.peers.first_mut() {
        let floor = meshlet_network::HUB_KEEPALIVE_SECS;
        if peer.persistent_keepalive_secs.unwrap_or(0) < floor {
            peer.persistent_keepalive_secs = Some(floor);
        }
    }
}
