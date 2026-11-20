//! Direct endpoint report.

use std::net::Ipv4Addr;

use meshlet_domain::DirectEndpointReport;

/// §12 P2P 直连候选（纯逻辑）：`listen_port` 为 `None`（未开启直连、生效
/// 端口未解析或全部候选被挡——WIN-PORT-1 B2 关闸态）→ `None`（上报省略，
/// 报一个本机绑不上的端口等于让对端拨死口）；有生效端口则携带它与枚举到
/// 的 RFC1918 局域网地址（可为空，空候选仍合法——对端仍可尝试公网观测
/// 地址）。生效端口与 conf `ListenPort`、防火墙放行三处同源（硬不变量，
/// 解析见 [`super::direct_port`]）。
pub(super) fn direct_report_from(
    listen_port: Option<u16>,
    lan_addrs: Vec<Ipv4Addr>,
) -> Option<DirectEndpointReport> {
    Some(DirectEndpointReport {
        listen_port: listen_port?,
        lan_addrs,
    })
}
