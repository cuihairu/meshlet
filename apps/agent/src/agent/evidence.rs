//! MTU probe decision.

use std::net::Ipv4Addr;

use meshlet_network::{DevicePlan, DEFAULT_TUNNEL_MTU};

/// Large-packet probe decision (pure logic): target = hub's overlay address (a
/// self-ping does not traverse the tunnel, so the evidence is distorted and is
/// skipped); payload = effective MTU - 28B (IP header 20B + ICMP header 8B).
/// Probing is skipped when the hub is unknown or the payload is 0. When the plan
/// does not configure an MTU, adapt to the underlay interface MTU
/// (lane/dataplane-speed): 1500 ethernet derives back to 1420 (unchanged behavior);
/// jumbo/PPPoE underlay derives a payload that fits the real path; when the
/// underlay reading is unavailable, fall back to the WireGuard default. An
/// explicit MTU in the plan wins - the kernel authority is always the server-side
/// plan, and the adaptation only affects the probe evidence.
pub(super) fn probe_decision(
    plan: &DevicePlan,
    underlay_mtu: Option<u32>,
) -> Option<(Ipv4Addr, u32)> {
    let hub = plan.hub_address.filter(|h| *h != plan.tunnel.address)?;
    let effective = plan.tunnel.mtu.unwrap_or_else(|| {
        underlay_mtu.map_or(DEFAULT_TUNNEL_MTU, meshlet_network::derive_tunnel_mtu)
    });
    let payload = effective.saturating_sub(28);
    (payload > 0).then_some((hub, payload))
}
