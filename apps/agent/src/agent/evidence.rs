//! MTU probe decision.

use std::net::Ipv4Addr;

use meshlet_network::{DevicePlan, DEFAULT_TUNNEL_MTU};

/// 大包探测决策（纯逻辑）：目标 = hub 的 overlay 地址（自 ping 不经过隧道，
/// 证据失真，跳过）；载荷 = 有效 MTU − 28B（IP 头 20B + ICMP 头 8B）。hub
/// 未知或载荷为 0 则不探测。计划未配置 MTU 时按底层接口 MTU 自适应
/// （lane/dataplane-speed）：1500 以太网推导回 1420（行为不变），jumbo/PPPoE
/// 底层推导出贴合真路径的载荷；底层读数不可得回退 WireGuard 默认。计划显式
/// 钉 MTU 时计划优先——内核权威始终是服务端计划，自适应只作用于探测证据。
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
