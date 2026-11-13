//! Endpoint parsing.

use std::net::Ipv4Addr;

use meshlet_domain::EndpointCandidate;

/// SEL-002：从直连端点字符串（`ip:port`）解析候选。无法解析（空 / 畸形）→
/// `None`（调用方按「无已下发直连候选」处理，不切换）。
pub(crate) fn parse_endpoint_candidate(endpoint: &str) -> Option<EndpointCandidate> {
    let (ip, port) = endpoint.rsplit_once(':')?;
    let ip = ip.parse::<Ipv4Addr>().ok()?;
    let port = port.parse::<u16>().ok()?;
    // 分类未知（端点字符串不携带 kind）：按私网判定，仅用于迟滞闸的
    // `current` 匹配——候选窗口按 (ip,port) 键匹配，kind 不影响相等判定
    // 之外的行为（EndpointCandidate 的 Ord 含 kind，但候选集来自同源，同
    // ip:port 的 kind 一致）。
    let kind = if meshlet_domain::is_private_ip(ip) {
        meshlet_domain::EndpointKind::Lan
    } else {
        meshlet_domain::EndpointKind::Public
    };
    Some(EndpointCandidate { ip, port, kind })
}
