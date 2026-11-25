//! Peer AllowedIPs derivation ([archive §7.2](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! Principle: AllowedIPs match the target routes; **never route everything
//! into the tunnel**. The first release routes by default only:
//! - the Meshlet Overlay range;
//! - explicitly published (`Applied`) remote LAN ranges;
//! - the corresponding Alias ranges.
//!
//! Two directions:
//! - [hub_peer_allowed_ips]: AllowedIPs for a device Peer on the VPS
//!   (this machine's Overlay /32 + that device's published LAN + Alias);
//! - [client_hub_peer_allowed_ips]: AllowedIPs for the client-to-VPS Peer
//!   (the entire Overlay + **other** devices' published LAN + Alias; a
//!   device's own published LAN is not fed back into the tunnel to avoid loops).

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

/// Collect a device's "published" LAN destination ranges and Alias ranges.
fn published_destinations<'a>(
    gateway_device_id: &DeviceId,
    lan_routes: &'a [LanRoute],
    alias_mappings: &'a [AliasMapping],
) -> Vec<Ipv4Cidr> {
    let mut out = Vec::new();
    for route in lan_routes {
        if &route.gateway_device_id == gateway_device_id
            && is_published(route)
            && route.route_mode == crate::RouteMode::Direct
        {
            out.push(route.destination_cidr);
        }
    }
    for alias in alias_mappings {
        if is_published_alias(alias) {
            if let Some(route) = lan_routes.iter().find(|r| r.id == alias.lan_route_id) {
                // An Alias only enters AllowedIPs once its LAN route is published.
                if &route.gateway_device_id == gateway_device_id && is_published(route) {
                    out.push(alias.alias_cidr);
                }
            }
        }
    }
    out
}

/// Deduplicate and sort deterministically (network address first, then prefix length).
fn normalize(mut cidrs: Vec<Ipv4Cidr>) -> Vec<Ipv4Cidr> {
    cidrs.sort_by_key(|c| (u32::from(c.network()), c.prefix_len()));
    cidrs.dedup();
    cidrs
}

/// Hub side: AllowedIPs for a device Peer.
///
/// = this machine's Overlay /32 + that device's published LAN + Alias.
///
/// The device's virtual IP must sit inside the Overlay (IPAM guarantees this; the boundary is re-checked here).
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

/// Client side: AllowedIPs for the Peer to the VPS.
///
/// = the entire Overlay + other devices' published LAN + the corresponding Alias ranges.
pub fn client_hub_peer_allowed_ips(
    overlay_cidr: Ipv4Cidr,
    self_device_id: &DeviceId,
    lan_routes: &[LanRoute],
    alias_mappings: &[AliasMapping],
) -> Vec<Ipv4Cidr> {
    let mut cidrs = vec![overlay_cidr];
    for route in lan_routes {
        if &route.gateway_device_id != self_device_id
            && is_published(route)
            && route.route_mode == crate::RouteMode::Direct
        {
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

/// Device Peer entry in the VPS tunnel: one independent Peer per device (§7.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DevicePeer {
    pub device_id: DeviceId,
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
}

/// The VPS tunnel's device Peer list: one independent Peer per device, with distinct AllowedIPs.
///
/// The server uses this to "find the corresponding Peer for a target Overlay IP".
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

/// Aggregate all published routes (for config generation / test assertions).
pub fn all_published_routes(
    lan_routes: &[LanRoute],
    alias_mappings: &[AliasMapping],
) -> BTreeMap<DeviceId, Vec<Ipv4Cidr>> {
    let mut by_gateway: BTreeMap<DeviceId, Vec<Ipv4Cidr>> = BTreeMap::new();
    for route in lan_routes {
        if is_published(route) && route.route_mode == crate::RouteMode::Direct {
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
    use crate::SegmentId;
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

        // Only the local /32: unpublished/failed routes and Aliases never enter AllowedIPs.
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

        // dev-a's view: Overlay + dev-b's LAN + dev-b's Alias; excludes its own 192.168.1.0/24.
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
            approved_at: None,
            revoked_at: None,
            segment_id: SegmentId("seg-net-1".into()),
            labels: BTreeMap::new(),
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
            approved_at: None,
            revoked_at: None,
            segment_id: SegmentId("seg-net-1".into()),
            labels: BTreeMap::new(),
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
