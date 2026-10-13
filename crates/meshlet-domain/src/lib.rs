//! meshlet-domain：核心领域层。
//!
//! 覆盖 [存档 §5–§6](../../docs/review/chatgpt-2026-10-13.md) 的实体约束、
//! Overlay IPAM 与 CIDR 冲突检测，以及 [§11.3](../../docs/review/chatgpt-2026-10-13.md)
//! 的邀请 Token 安全。设计决策见
//! [ADR-004](../../docs/decisions/adr-004-overlay-ipam.md) /
//! [ADR-006](../../docs/decisions/adr-006-alias-prefix-nat.md) /
//! [ADR-009](../../docs/decisions/adr-009-config-revision-rollback.md)。

pub mod auth;
pub mod cidr;
pub mod conflict;
pub mod entities;
pub mod invites;
pub mod ipam;
pub mod peer_routes;
pub mod tokens;

pub use cidr::{CidrError, Ipv4Cidr};
pub use conflict::{
    against_existing_routes, alias_alias_overlap, alias_target_mismatch, check_network,
    lan_route_conflicts, overlay_alias_overlap, Conflict, ConflictCode, ConflictKind, RouteSource,
};
pub use entities::{
    AliasError, AliasMapping, ApplyStatus, ConfigRevision, DesiredStateStatus, Device, DeviceError,
    DeviceId, DeviceKey, DeviceRegistry, DeviceStatus, InviteId, LanRoute, Network, NetworkId,
    NetworkStatus, Platform, RegistryError, ReturnPathMode, RevisionError, RouteMode, Timestamp,
    TranslationMode, UserId,
};
pub use invites::{generate_token, token_hash, Invite, InviteError};
pub use ipam::{Ipam, IpamError};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_overlay_is_the_documented_default_not_a_constant() {
        // ADR-004：10.240.0.0/16 是默认值建议，不是协议常量——
        // 任意合法网段都必须能构造 Network。
        let custom: Ipv4Cidr = "172.30.0.0/16".parse().unwrap();
        let n = Network::new(
            NetworkId("n".into()),
            "custom",
            custom,
            "2026-10-14T08:00:00Z".into(),
        );
        assert_eq!(n.overlay_cidr, custom);
    }
}
