//! Direct-connect scope derivation.

use meshlet_domain::Ipv4Cidr;
use meshlet_network::DevicePlan;

/// §12：本设备可路由网段 = hub peer 的 AllowedIPs 中**包含本设备 overlay
/// 地址**的那条。分段网络时 hub peer 有多条 AllowedIPs 且 `normalize` 排序
/// 不保证（`allowed_ips[0]` 不一定是所属段），包含关系才是唯一可靠判据；
/// 与 `peer_endpoints_for` 的 scope 推导同一口径。取不到（无 hub peer /
/// 地址越出所有段）返回 `None`——无法安全下发 `/32`，保持 hub 中继。
/// 本设备可路由网段（直连 AllowedIPs `/32` 的冲突边界）：hub peer 的
/// AllowedIPs 里**最长前缀**且包含本机 overlay 地址的 CIDR。多段重叠时
/// 最具体的才是本机自己的段（宽段可能覆盖其他段）。
pub(super) fn direct_scope(plan: &DevicePlan) -> Option<Ipv4Cidr> {
    plan.tunnel
        .peers
        .iter()
        .flat_map(|peer| peer.allowed_ips.iter().copied())
        .filter(|cidr| cidr.contains(plan.tunnel.address))
        .max_by_key(|cidr| cidr.prefix_len())
}
