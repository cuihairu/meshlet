//! Endpoint parsing.

use std::net::Ipv4Addr;

use meshlet_domain::EndpointCandidate;

/// SEL-002: parse a candidate from a direct endpoint string (`ip:port`).
/// Unparseable (empty / malformed) -> `None` (the caller treats it as "no direct candidate delivered" and does not switch).
pub(crate) fn parse_endpoint_candidate(endpoint: &str) -> Option<EndpointCandidate> {
    let (ip, port) = endpoint.rsplit_once(':')?;
    let ip = ip.parse::<Ipv4Addr>().ok()?;
    let port = port.parse::<u16>().ok()?;
    // Kind is unknown (the endpoint string carries no kind): decide by privacy, used only for the
    // hysteresis gate's `current` match - the candidate window matches on the (ip,port) key, so kind affects no
    // behavior beyond equality (EndpointCandidate's Ord includes kind, but the candidate set comes from the same
    // source, so the kind for a given ip:port is consistent).
    let kind = if meshlet_domain::is_private_ip(ip) {
        meshlet_domain::EndpointKind::Lan
    } else {
        meshlet_domain::EndpointKind::Public
    };
    Some(EndpointCandidate { ip, port, kind })
}
