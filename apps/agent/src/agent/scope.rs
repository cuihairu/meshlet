//! Direct-connect scope derivation.

use meshlet_domain::Ipv4Cidr;
use meshlet_network::DevicePlan;

/// §12: this device's routable segment = the entry in the hub peer's AllowedIPs
/// that **contains this device's overlay address**. In a segmented network the
/// hub peer has multiple AllowedIPs and `normalize` ordering is not guaranteed
/// (`allowed_ips[0]` is not necessarily the owning segment); the containment
/// relation is the only reliable criterion - same criterion as `peer_endpoints_for`'s
/// scope derivation. Unreachable (no hub peer / the address falls outside every
/// segment) returns `None` - a `/32` cannot be safely issued, so keep the hub
/// relay. This device's routable segment (the conflict boundary for direct
/// AllowedIPs `/32`): the **longest-prefix** CIDR in the hub peer's AllowedIPs
/// that contains this machine's overlay address. When segments overlap, the
/// most specific one is this machine's own segment (a wide segment may cover others).
pub(super) fn direct_scope(plan: &DevicePlan) -> Option<Ipv4Cidr> {
    plan.tunnel
        .peers
        .iter()
        .flat_map(|peer| peer.allowed_ips.iter().copied())
        .filter(|cidr| cidr.contains(plan.tunnel.address))
        .max_by_key(|cidr| cidr.prefix_len())
}
