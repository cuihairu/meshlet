//! 直连 Peer 的 AllowedIPs `/32` 拆分与冲突检查。

use std::net::Ipv4Addr;

use crate::cidr::Ipv4Cidr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DirectPeerError {
    #[error("peer virtual IP {peer} outside routable scope {scope}")]
    PeerOutsideScope { peer: Ipv4Addr, scope: Ipv4Cidr },
    #[error("peer virtual IP {0} is this device's own address")]
    IsSelf(Ipv4Addr),
}

/// 直连 Peer 的 AllowedIPs：**只**写对端 overlay `/32`（任务书）。返回前
/// 复核两条冲突边界：对端虚拟 IP 必须在路由范围内、不得是自己。
pub fn direct_peer_allowed_ips(
    scope_cidr: Ipv4Cidr,
    self_virtual_ip: Ipv4Addr,
    peer_virtual_ip: Ipv4Addr,
) -> Result<Vec<Ipv4Cidr>, DirectPeerError> {
    if peer_virtual_ip == self_virtual_ip {
        return Err(DirectPeerError::IsSelf(peer_virtual_ip));
    }
    if !scope_cidr.contains(peer_virtual_ip) {
        return Err(DirectPeerError::PeerOutsideScope {
            peer: peer_virtual_ip,
            scope: scope_cidr,
        });
    }
    Ok(vec![Ipv4Cidr::new(peer_virtual_ip, 32).expect("valid /32")])
}

#[cfg(test)]
mod tests {
    use super::{direct_peer_allowed_ips, DirectPeerError};
    use crate::p2p::test_support::{cidr, OVERLAY};

    // ------------------------------------------------- AllowedIPs /32 ----

    #[test]
    fn direct_peer_allowed_ips_is_only_the_peer_32() {
        let ips = direct_peer_allowed_ips(
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            "10.240.0.3".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(ips, vec!["10.240.0.3/32".parse().unwrap()]);
    }

    #[test]
    fn direct_peer_rejects_self() {
        let err = direct_peer_allowed_ips(
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            "10.240.0.2".parse().unwrap(),
        )
        .unwrap_err();
        assert_eq!(err, DirectPeerError::IsSelf("10.240.0.2".parse().unwrap()));
    }

    #[test]
    fn direct_peer_rejects_outside_scope() {
        let err = direct_peer_allowed_ips(
            cidr("10.240.1.0/24"),
            "10.240.1.2".parse().unwrap(),
            "10.240.9.9".parse().unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, DirectPeerError::PeerOutsideScope { .. }));
    }
}
