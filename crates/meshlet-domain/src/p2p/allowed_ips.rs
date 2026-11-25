//! Splitting AllowedIPs into `/32`s and conflict checks for a direct Peer.

use std::net::Ipv4Addr;

use crate::cidr::Ipv4Cidr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DirectPeerError {
    #[error("peer virtual IP {peer} outside routable scope {scope}")]
    PeerOutsideScope { peer: Ipv4Addr, scope: Ipv4Cidr },
    #[error("peer virtual IP {0} is this device's own address")]
    IsSelf(Ipv4Addr),
}

/// AllowedIPs for a direct Peer: write **only** the peer's overlay `/32` (task spec);
/// two conflict bounds are rechecked first: the peer virtual IP must be in scope and not self.
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
