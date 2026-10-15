//! Peer AllowedIPs 推导（[存档 §7.2](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 原则：AllowedIPs 与目标路由一致，**不得全量指隧道**。
//! 第一版默认只路由：
//! - Meshlet Overlay 网段；
//! - 明确发布（`Applied`）的远端 LAN 网段；
//! - 对应的 Alias 网段。
//!
//! 两个方向：
//! - [hub_peer_allowed_ips]：VPS 上某设备 Peer 的 AllowedIPs
//!   （本机 Overlay /32 + 该设备发布的 LAN + Alias）；
//! - [client_hub_peer_allowed_ips]：客户端到 VPS Peer 的 AllowedIPs
//!   （整个 Overlay + **其他**设备发布的 LAN + Alias；自己发布的本地网段
//!   不回灌隧道，避免环路）。

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::entities::{AliasMapping, DesiredStateStatus, DeviceId, LanRoute};
use crate::Ipv4Cidr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerRouteError {
    #[error("device {device_id} virtual IP {virtual_ipv4} is outside the overlay CIDR")]
    DeviceOutsideOverlay {
        device_id: DeviceId,
        virtual_ipv4: Ipv4Addr,
    },
}

fn is_published(route: &LanRoute) -> bool {
    route.status == DesiredStateStatus::Applied
}

fn is_published_alias(alias: &AliasMapping) -> bool {
    alias.status == DesiredStateStatus::Applied
}

/// 汇总某设备「已发布」的 LAN 目标网段与 Alias 网段。
fn published_destinations<'a>(
    gateway_device_id: &DeviceId,
    lan_routes: &'a [LanRoute],
    alias_mappings: &'a [AliasMapping],
) -> Vec<Ipv4Cidr> {
    let mut out = Vec::new();
    for route in lan_routes {
        if &route.gateway_device_id == gateway_device_id && is_published(route) {
            out.push(route.destination_cidr);
        }
    }
    for alias in alias_mappings {
        if is_published_alias(alias) {
            if let Some(route) = lan_routes.iter().find(|r| r.id == alias.lan_route_id) {
                // Alias 只有在对应 LAN 路由已发布时才进 AllowedIPs。
                if &route.gateway_device_id == gateway_device_id && is_published(route) {
                    out.push(alias.alias_cidr);
                }
            }
        }
    }
    out
}

/// 去重 + 确定性排序（先网络地址，后前缀长度）。
fn normalize(mut cidrs: Vec<Ipv4Cidr>) -> Vec<Ipv4Cidr> {
    cidrs.sort_by_key(|c| (u32::from(c.network()), c.prefix_len()));
    cidrs.dedup();
    cidrs
}

/// VPS 侧：某设备 Peer 的 AllowedIPs。
///
/// = 本机 Overlay /32 + 该设备已发布的 LAN 目标网段 + 对应 Alias 网段。
///
/// 设备的虚拟 IP 必须在 Overlay 内（IPAM 保证，这里再核一次边界）。
pub fn hub_peer_allowed_ips(
    overlay_cidr: Ipv4Cidr,
    device_id: &DeviceId,
    device_virtual_ipv4: Ipv4Addr,
    lan_routes: &[LanRoute],
    alias_mappings: &[AliasMapping],
) -> Result<Vec<Ipv4Cidr>, PeerRouteError> {
    if !overlay_cidr.contains(device_virtual_ipv4) {
        return Err(PeerRouteError::DeviceOutsideOverlay {
            device_id: device_id.clone(),
            virtual_ipv4: device_virtual_ipv4,
        });
    }
    let mut cidrs = vec![Ipv4Cidr::new(device_virtual_ipv4, 32).expect("valid /32")];
    cidrs.extend(published_destinations(
        device_id,
        lan_routes,
        alias_mappings,
    ));
    Ok(normalize(cidrs))
}

/// 客户端侧：到 VPS Peer 的 AllowedIPs。
///
/// = 整个 Overlay + 其他设备已发布的 LAN 目标网段 + 对应 Alias 网段。
pub fn client_hub_peer_allowed_ips(
    overlay_cidr: Ipv4Cidr,
    self_device_id: &DeviceId,
    lan_routes: &[LanRoute],
    alias_mappings: &[AliasMapping],
) -> Vec<Ipv4Cidr> {
    let mut cidrs = vec![overlay_cidr];
    for route in lan_routes {
        if &route.gateway_device_id != self_device_id && is_published(route) {
            cidrs.push(route.destination_cidr);
        }
    }
    for alias in alias_mappings {
        if is_published_alias(alias) {
            if let Some(route) = lan_routes.iter().find(|r| r.id == alias.lan_route_id) {
                if &route.gateway_device_id != self_device_id && is_published(route) {
                    cidrs.push(alias.alias_cidr);
                }
            }
        }
    }
    normalize(cidrs)
}

/// VPS 隧道中的设备 Peer 条目：每设备独立 Peer（§7.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePeer {
    pub device_id: DeviceId,
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
}

/// VPS 隧道的设备 Peer 列表：每设备独立 Peer，AllowedIPs 互不相同。
///
/// 服务端据此「根据目标 Overlay IP 找到对应 Peer」。
pub fn hub_device_peers(
    overlay_cidr: Ipv4Cidr,
    devices: &[crate::entities::Device],
    lan_routes: &[LanRoute],
    alias_mappings: &[AliasMapping],
) -> Result<Vec<DevicePeer>, PeerRouteError> {
    devices
        .iter()
        .map(|device| {
            let allowed_ips = hub_peer_allowed_ips(
                overlay_cidr,
                &device.id,
                device.virtual_ipv4,
                lan_routes,
                alias_mappings,
            )?;
            Ok(DevicePeer {
                device_id: device.id.clone(),
                public_key: device.public_key.clone(),
                allowed_ips,
            })
        })
        .collect()
}

/// 汇总全网已发布路由（供配置生成/测试断言用）。
pub fn all_published_routes(
    lan_routes: &[LanRoute],
    alias_mappings: &[AliasMapping],
) -> BTreeMap<DeviceId, Vec<Ipv4Cidr>> {
    let mut by_gateway: BTreeMap<DeviceId, Vec<Ipv4Cidr>> = BTreeMap::new();
    for route in lan_routes {
        if is_published(route) {
            by_gateway
                .entry(route.gateway_device_id.clone())
                .or_default()
                .push(route.destination_cidr);
        }
    }
    for alias in alias_mappings {
        if is_published_alias(alias) {
            if let Some(route) = lan_routes.iter().find(|r| r.id == alias.lan_route_id) {
                if is_published(route) {
                    by_gateway
                        .entry(route.gateway_device_id.clone())
                        .or_default()
                        .push(alias.alias_cidr);
                }
            }
        }
    }
    for cidrs in by_gateway.values_mut() {
        *cidrs = normalize(cidrs.clone());
    }
    by_gateway
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{
        AliasMappingId, LanRouteId, NetworkId, ReturnPathMode, RouteMode, TranslationMode,
    };
    use crate::Timestamp;

    fn ts() -> Timestamp {
        "2026-10-14T00:00:00Z".into()
    }

    fn route(id: &str, gateway: &str, dest: &str, status: DesiredStateStatus) -> LanRoute {
        LanRoute {
            id: LanRouteId(id.into()),
            network_id: NetworkId("net-1".into()),
            gateway_device_id: DeviceId(gateway.into()),
            destination_cidr: dest.parse().unwrap(),
            route_mode: RouteMode::Direct,
            return_path_mode: ReturnPathMode::DualRoute,
            status,
            created_at: ts(),
        }
    }

    fn alias(
        id: &str,
        lan_route_id: &str,
        alias_cidr: &str,
        target: &str,
        status: DesiredStateStatus,
    ) -> AliasMapping {
        AliasMapping {
            id: AliasMappingId(id.into()),
            network_id: NetworkId("net-1".into()),
            lan_route_id: LanRouteId(lan_route_id.into()),
            alias_cidr: alias_cidr.parse().unwrap(),
            target_cidr: target.parse().unwrap(),
            translation_mode: TranslationMode::DnatOnly,
            status,
        }
    }

    const OVERLAY: &str = "10.240.0.0/16";

    #[test]
    fn hub_peer_routes_only_own_lan_and_alias() {
        let routes = vec![
            route(
                "r-1",
                "dev-a",
                "192.168.1.0/24",
                DesiredStateStatus::Applied,
            ),
            route(
                "r-2",
                "dev-b",
                "192.168.2.0/24",
                DesiredStateStatus::Applied,
            ),
        ];
        let aliases = vec![alias(
            "a-1",
            "r-1",
            "10.241.1.0/24",
            "192.168.1.0/24",
            DesiredStateStatus::Applied,
        )];

        let ips = hub_peer_allowed_ips(
            OVERLAY.parse().unwrap(),
            &DeviceId("dev-a".into()),
            "10.240.0.2".parse().unwrap(),
            &routes,
            &aliases,
        )
        .unwrap();

        assert_eq!(
            ips,
            vec![
                "10.240.0.2/32".parse().unwrap(),
                "10.241.1.0/24".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn hub_peer_excludes_pending_and_failed_routes() {
        let routes = vec![
            route(
                "r-1",
                "dev-a",
                "192.168.1.0/24",
                DesiredStateStatus::Pending,
            ),
            route("r-2", "dev-a", "192.168.2.0/24", DesiredStateStatus::Failed),
        ];
        let aliases = vec![alias(
            "a-1",
            "r-1",
            "10.241.1.0/24",
            "192.168.1.0/24",
            DesiredStateStatus::Applied,
        )];

        let ips = hub_peer_allowed_ips(
            OVERLAY.parse().unwrap(),
            &DeviceId("dev-a".into()),
            "10.240.0.2".parse().unwrap(),
            &routes,
            &aliases,
        )
        .unwrap();

        // 只有本机 /32：未发布/失败的路由与 Alias 都不进 AllowedIPs。
        assert_eq!(ips, vec!["10.240.0.2/32".parse().unwrap()]);
    }

    #[test]
    fn client_routes_overlay_plus_others_lan_but_not_own() {
        let routes = vec![
            route(
                "r-1",
                "dev-a",
                "192.168.1.0/24",
                DesiredStateStatus::Applied,
            ),
            route(
                "r-2",
                "dev-b",
                "192.168.2.0/24",
                DesiredStateStatus::Applied,
            ),
        ];
        let aliases = vec![
            alias(
                "a-1",
                "r-1",
                "10.241.1.0/24",
                "192.168.1.0/24",
                DesiredStateStatus::Applied,
            ),
            alias(
                "a-2",
                "r-2",
                "10.241.2.0/24",
                "192.168.2.0/24",
                DesiredStateStatus::Applied,
            ),
        ];

        // dev-a 的视角：Overlay + dev-b 的 LAN + dev-b 的 Alias；不含自己的 192.168.1.0/24。
        let ips = client_hub_peer_allowed_ips(
            OVERLAY.parse().unwrap(),
            &DeviceId("dev-a".into()),
            &routes,
            &aliases,
        );

        assert_eq!(
            ips,
            vec![
                "10.240.0.0/16".parse().unwrap(),
                "10.241.2.0/24".parse().unwrap(),
                "192.168.2.0/24".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn client_with_no_remote_routes_gets_overlay_only() {
        let routes = vec![route(
            "r-1",
            "dev-a",
            "192.168.1.0/24",
            DesiredStateStatus::Applied,
        )];
        let aliases = vec![];

        let ips = client_hub_peer_allowed_ips(
            OVERLAY.parse().unwrap(),
            &DeviceId("dev-a".into()),
            &routes,
            &aliases,
        );

        assert_eq!(ips, vec![OVERLAY.parse().unwrap()]);
    }

    #[test]
    fn duplicate_entries_are_deduped_and_sorted() {
        let routes = vec![
            route(
                "r-1",
                "dev-a",
                "192.168.1.0/24",
                DesiredStateStatus::Applied,
            ),
            route(
                "r-2",
                "dev-a",
                "192.168.1.0/24",
                DesiredStateStatus::Applied,
            ),
        ];
        let aliases = vec![];

        let ips = hub_peer_allowed_ips(
            OVERLAY.parse().unwrap(),
            &DeviceId("dev-a".into()),
            "10.240.0.2".parse().unwrap(),
            &routes,
            &aliases,
        )
        .unwrap();

        assert_eq!(
            ips,
            vec![
                "10.240.0.2/32".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn alias_of_unpublished_route_is_excluded_even_if_alias_applied() {
        let routes = vec![route(
            "r-1",
            "dev-a",
            "192.168.1.0/24",
            DesiredStateStatus::Pending,
        )];
        let aliases = vec![alias(
            "a-1",
            "r-1",
            "10.241.1.0/24",
            "192.168.1.0/24",
            DesiredStateStatus::Applied,
        )];

        let ips = hub_peer_allowed_ips(
            OVERLAY.parse().unwrap(),
            &DeviceId("dev-a".into()),
            "10.240.0.2".parse().unwrap(),
            &routes,
            &aliases,
        )
        .unwrap();

        assert_eq!(ips, vec!["10.240.0.2/32".parse().unwrap()]);
    }

    #[test]
    fn hub_peer_rejects_device_outside_overlay() {
        let err = hub_peer_allowed_ips(
            OVERLAY.parse().unwrap(),
            &DeviceId("dev-a".into()),
            "10.241.0.2".parse().unwrap(),
            &[],
            &[],
        )
        .unwrap_err();

        assert_eq!(
            err,
            PeerRouteError::DeviceOutsideOverlay {
                device_id: DeviceId("dev-a".into()),
                virtual_ipv4: "10.241.0.2".parse().unwrap(),
            }
        );
    }

    #[test]
    fn hub_device_peers_gives_each_device_independent_peer() {
        use crate::entities::{Device, DeviceId as Did, DeviceStatus, Platform};

        let device = |id: &str, ip: &str| Device {
            id: Did(id.into()),
            network_id: NetworkId("net-1".into()),
            name: id.into(),
            virtual_ipv4: ip.parse().unwrap(),
            public_key: format!("pub-{id}"),
            platform: Platform::Linux,
            status: DeviceStatus::Active,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: ts(),
            revoked_at: None,
        };
        let devices = vec![device("dev-a", "10.240.0.2"), device("dev-b", "10.240.0.3")];
        let routes = vec![route(
            "r-2",
            "dev-b",
            "192.168.2.0/24",
            DesiredStateStatus::Applied,
        )];

        let peers = hub_device_peers(OVERLAY.parse().unwrap(), &devices, &routes, &[]).unwrap();

        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].device_id, DeviceId("dev-a".into()));
        assert_eq!(peers[0].public_key, "pub-dev-a");
        assert_eq!(peers[0].allowed_ips, vec!["10.240.0.2/32".parse().unwrap()]);
        assert_eq!(peers[1].device_id, DeviceId("dev-b".into()));
        assert_eq!(
            peers[1].allowed_ips,
            vec![
                "10.240.0.3/32".parse().unwrap(),
                "192.168.2.0/24".parse().unwrap()
            ]
        );
    }

    #[test]
    fn hub_device_peers_rejects_device_outside_overlay() {
        use crate::entities::{Device, DeviceId as Did, DeviceStatus, Platform};

        let devices = vec![Device {
            id: Did("dev-a".into()),
            network_id: NetworkId("net-1".into()),
            name: "dev-a".into(),
            virtual_ipv4: "10.241.0.2".parse().unwrap(),
            public_key: "pub-a".into(),
            platform: Platform::Linux,
            status: DeviceStatus::Active,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: ts(),
            revoked_at: None,
        }];

        let err = hub_device_peers(OVERLAY.parse().unwrap(), &devices, &[], &[]).unwrap_err();
        assert!(matches!(err, PeerRouteError::DeviceOutsideOverlay { .. }));
    }

    #[test]
    fn all_published_routes_groups_by_gateway() {
        let routes = vec![
            route(
                "r-1",
                "dev-a",
                "192.168.1.0/24",
                DesiredStateStatus::Applied,
            ),
            route(
                "r-2",
                "dev-b",
                "192.168.2.0/24",
                DesiredStateStatus::Applied,
            ),
            route(
                "r-3",
                "dev-a",
                "192.168.3.0/24",
                DesiredStateStatus::Pending,
            ),
        ];
        let aliases = vec![alias(
            "a-1",
            "r-1",
            "10.241.1.0/24",
            "192.168.1.0/24",
            DesiredStateStatus::Applied,
        )];

        let by_gateway = all_published_routes(&routes, &aliases);

        assert_eq!(
            by_gateway.get(&DeviceId("dev-a".into())),
            Some(&vec![
                "10.241.1.0/24".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
            ])
        );
        assert_eq!(
            by_gateway.get(&DeviceId("dev-b".into())),
            Some(&vec!["192.168.2.0/24".parse().unwrap()])
        );
    }
}
