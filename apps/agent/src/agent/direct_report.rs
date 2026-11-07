//! Direct endpoint report.

use std::net::Ipv4Addr;

use meshlet_config::DirectConnectConfig;
use meshlet_domain::DirectEndpointReport;

/// §12 P2P 直连候选（纯逻辑）：未开启直连 → `None`（上报省略）；开启则携带
/// WireGuard 监听端口与枚举到的 RFC1918 局域网地址（可为空，空候选仍合法——
/// 对端仍可尝试公网观测地址）。
pub(super) fn direct_report_from(
    direct_connect: &DirectConnectConfig,
    lan_addrs: Vec<Ipv4Addr>,
) -> Option<DirectEndpointReport> {
    if !direct_connect.enabled {
        return None;
    }
    Some(DirectEndpointReport {
        listen_port: direct_connect.listen_port,
        lan_addrs,
    })
}
