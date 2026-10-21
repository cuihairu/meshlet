//! Pure cross-platform planning shared by hub and device backends.
//!
//! Inputs are canonicalized before analysis and compilation. Conflict reports,
//! peer ordering, gateway assignments, and device plans therefore do not depend
//! on persistence or API insertion order.

use std::collections::BTreeMap;

use meshlet_domain::{
    check_network, hub_device_peers, validate_device_segment, AliasMapping, Conflict,
    DesiredStateStatus, Device, DeviceId, DevicePeer as HubDevicePeer, Ipv4Cidr, LanRoute,
    NetworkId, PeerRouteError, ReturnPathMode, RouteMode, Segment, SegmentGrant,
    SegmentGrantStatus, SegmentId, TranslationMode,
};

pub use meshlet_domain::{ConflictCode, ConflictKind};

fn canonical_conflicts(mut conflicts: Vec<Conflict>) -> Vec<Conflict> {
    conflicts.sort_by(|left, right| (left.code, &left.detail).cmp(&(right.code, &right.detail)));
    conflicts.dedup();
    conflicts
}

fn canonical_objects<T>(mut values: Vec<T>, key: impl Fn(&T, &T) -> std::cmp::Ordering) -> Vec<T> {
    values.sort_by(|left, right| key(left, right));
    values.dedup_by(|left, right| key(left, right) == std::cmp::Ordering::Equal);
    values
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("plan contains an object from another network")]
    ForeignObject,
    #[error("gateway device {0} was not found in the device set")]
    UnknownGateway(DeviceId),
    #[error("device {0} is outside the overlay")]
    DeviceOutsideOverlay(DeviceId),
    #[error("device {0} has no active segment assignment")]
    UnknownDeviceSegment(DeviceId),
    #[error("route {0} must map to exactly one alias")]
    AliasRouteAmbiguous(meshlet_domain::LanRouteId),
    #[error("plan contains duplicate device addresses, segment IDs, or alias bindings")]
    AmbiguousInput,
    #[error("network conflicts must be resolved before compilation: {0:?}")]
    NetworkConflicts(Vec<Conflict>),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Route {
    pub destination: Ipv4Cidr,
    pub gateway: std::net::Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AliasRoute {
    pub id: meshlet_domain::AliasMappingId,
    pub lan_route_id: meshlet_domain::LanRouteId,
    pub alias_cidr: Ipv4Cidr,
    pub target_cidr: Ipv4Cidr,
    pub translation_mode: TranslationMode,
    pub snat_return_path: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GatewayRoutePlan {
    pub device_id: DeviceId,
    pub virtual_address: std::net::Ipv4Addr,
    pub direct_routes: Vec<Ipv4Cidr>,
    pub aliases: Vec<AliasRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceRoutePlan {
    pub device_id: DeviceId,
    pub virtual_address: std::net::Ipv4Addr,
    pub segment_id: SegmentId,
    pub allowed_ips: Vec<Ipv4Cidr>,
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetworkPlan {
    pub network_id: NetworkId,
    pub overlay: Ipv4Cidr,
    pub hub_peers: Vec<HubDevicePeer>,
    pub gateways: Vec<GatewayRoutePlan>,
    pub devices: Vec<DeviceRoutePlan>,
}

fn has_unique_ids<T, K>(values: &[T], key: impl Fn(&T) -> K) -> bool
where
    K: Ord,
{
    values
        .iter()
        .map(key)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == values.len()
}

/// Return server-known conflicts for one network in canonical order.
pub fn analyze_network_conflicts(
    overlay: Ipv4Cidr,
    aliases: &[AliasMapping],
    routes: &[LanRoute],
    segments: &[Segment],
    server_routes: &[Ipv4Cidr],
) -> Vec<Conflict> {
    let aliases = canonical_objects(aliases.to_vec(), |left, right| left.id.cmp(&right.id));
    let routes = canonical_objects(routes.to_vec(), |left, right| left.id.cmp(&right.id));
    let segments = canonical_objects(segments.to_vec(), |left, right| left.id.cmp(&right.id));
    let server_routes = canonical_objects(server_routes.to_vec(), |left, right| left.cmp(right));
    canonical_conflicts(check_network(
        overlay,
        &aliases,
        &routes,
        &segments,
        &server_routes,
        Some(&[]),
    ))
}

/// Validate all server-known relationships in one network, independent of input order.
///
/// The maturity model follows central coordination systems such as Tailscale and
/// NetBird: prefix ownership is checked against the complete desired state first;
/// only the unique, conflict-free set is compiled into peer routes and gateway
/// assignments. Segment grants then narrow which destinations a source may receive.
#[allow(clippy::too_many_arguments)]
pub fn validate_network(
    network_id: &NetworkId,
    overlay: Ipv4Cidr,
    devices: &[Device],
    segments: &[Segment],
    grants: &[SegmentGrant],
    routes: &[LanRoute],
    aliases: &[AliasMapping],
    server_routes: &[Ipv4Cidr],
) -> Vec<Conflict> {
    let active_devices = devices
        .iter()
        .filter(|device| &device.network_id == network_id && device.is_active())
        .collect::<Vec<_>>();
    let active_segments = segments
        .iter()
        .filter(|segment| {
            &segment.network_id == network_id
                && segment.status == meshlet_domain::SegmentStatus::Active
        })
        .collect::<Vec<_>>();
    let published_routes = routes
        .iter()
        .filter(|route| {
            &route.network_id == network_id && route.status == DesiredStateStatus::Applied
        })
        .collect::<Vec<_>>();
    let published_aliases = aliases
        .iter()
        .filter(|alias| {
            &alias.network_id == network_id && alias.status == DesiredStateStatus::Applied
        })
        .collect::<Vec<_>>();
    let mut conflicts = analyze_network_conflicts(
        overlay,
        &published_aliases
            .iter()
            .map(|alias| (**alias).clone())
            .collect::<Vec<_>>(),
        &published_routes
            .iter()
            .map(|route| (**route).clone())
            .collect::<Vec<_>>(),
        &active_segments
            .iter()
            .map(|segment| (**segment).clone())
            .collect::<Vec<_>>(),
        server_routes,
    );

    if !has_unique_ids(&active_devices, |device| &device.id)
        || !has_unique_ids(&active_segments, |segment| &segment.id)
        || !has_unique_ids(&published_routes, |route| &route.id)
        || !has_unique_ids(&published_aliases, |alias| &alias.id)
    {
        conflicts.push(Conflict {
            code: ConflictCode::AmbiguousInput,
            kind: ConflictKind::ServerKnown,
            detail: "active devices, segments, routes, and aliases must have unique IDs".into(),
        });
    }

    if !has_unique_ids(grants, |grant| grant.id.clone()) {
        conflicts.push(Conflict {
            code: ConflictCode::AmbiguousInput,
            kind: ConflictKind::ServerKnown,
            detail: "segment grants must have unique IDs".into(),
        });
    }

    let active_grants = grants
        .iter()
        .filter(|grant| grant.status == SegmentGrantStatus::Applied)
        .collect::<Vec<_>>();
    if !has_unique_ids(&active_grants, |grant| {
        (&grant.source_segment_id, &grant.destination_segment_id)
    }) {
        conflicts.push(Conflict {
            code: ConflictCode::AmbiguousInput,
            kind: ConflictKind::ServerKnown,
            detail: "applied segment grants must have unique source-destination pairs".into(),
        });
    }

    for grant in &active_grants {
        let source_known = active_segments
            .iter()
            .any(|segment| segment.id == grant.source_segment_id);
        let destination_known = active_segments
            .iter()
            .any(|segment| segment.id == grant.destination_segment_id);
        if !source_known || !destination_known {
            conflicts.push(Conflict {
                code: ConflictCode::UnknownSegmentGrantEndpoint,
                kind: ConflictKind::ServerKnown,
                detail: format!(
                    "grant {} references unknown segment endpoints {} and {}",
                    grant.id, grant.source_segment_id, grant.destination_segment_id
                ),
            });
        }
    }

    if !has_unique_ids(&active_devices, |device| device.virtual_ipv4) {
        conflicts.push(Conflict {
            code: ConflictCode::DuplicateDeviceAddress,
            kind: ConflictKind::ServerKnown,
            detail: "active devices must have unique overlay addresses".into(),
        });
    }

    if grants.iter().any(|grant| grant.network_id != *network_id)
        || devices
            .iter()
            .any(|device| device.network_id != *network_id)
        || segments
            .iter()
            .any(|segment| segment.network_id != *network_id)
        || routes.iter().any(|route| route.network_id != *network_id)
        || aliases.iter().any(|alias| alias.network_id != *network_id)
    {
        conflicts.push(Conflict {
            code: ConflictCode::ForeignObject,
            kind: ConflictKind::ServerKnown,
            detail: "every object passed to a network plan must belong to that network".into(),
        });
    }

    let routes_by_id = published_routes
        .iter()
        .map(|route| (&route.id, *route))
        .collect::<BTreeMap<_, _>>();
    if published_routes.iter().any(|route| {
        !active_devices
            .iter()
            .any(|device| device.id == route.gateway_device_id)
    }) {
        conflicts.push(Conflict {
            code: ConflictCode::UnknownGateway,
            kind: ConflictKind::ServerKnown,
            detail: "every published route needs an active gateway device in the same network"
                .into(),
        });
    }
    let mut aliases_by_route =
        published_aliases
            .iter()
            .fold(BTreeMap::<_, Vec<_>>::new(), |mut aliases, alias| {
                aliases.entry(&alias.lan_route_id).or_default().push(alias);
                aliases
            });
    for route_aliases in aliases_by_route.values_mut() {
        route_aliases.sort_by(|left, right| left.id.cmp(&right.id));
    }
    for (route_id, route_aliases) in &aliases_by_route {
        let route = routes_by_id.get(route_id);
        if route.is_none() {
            conflicts.push(Conflict {
                code: ConflictCode::OrphanAliasMapping,
                kind: ConflictKind::ServerKnown,
                detail: format!("alias {} has no published route", route_aliases[0].id),
            });
        } else if route_aliases.len() != 1 {
            conflicts.push(Conflict {
                code: ConflictCode::AliasRouteAmbiguous,
                kind: ConflictKind::ServerKnown,
                detail: format!("route {route_id} must map to exactly one alias"),
            });
        }
    }

    for device in &active_devices {
        if validate_device_segment(
            device.virtual_ipv4,
            network_id,
            &device.segment_id,
            overlay,
            &active_segments
                .iter()
                .map(|segment| (**segment).clone())
                .collect::<Vec<_>>(),
        )
        .is_err()
        {
            conflicts.push(Conflict {
                code: ConflictCode::DeviceOutsideSegment,
                kind: ConflictKind::ServerKnown,
                detail: format!(
                    "device {} must belong to its assigned segment inside overlay {overlay}",
                    device.id
                ),
            });
        }
    }

    canonical_conflicts(conflicts)
}

/// Deterministically compile hub peers for one network.
pub fn plan_hub_peers(
    overlay: Ipv4Cidr,
    devices: &[Device],
    routes: &[LanRoute],
    aliases: &[AliasMapping],
) -> Result<Vec<HubDevicePeer>, PeerRouteError> {
    let mut peers = hub_device_peers(overlay, devices, routes, aliases)?;
    peers.sort_by(|left, right| left.device_id.cmp(&right.device_id));
    Ok(peers)
}

fn active_devices_by_id<'a>(
    devices: &'a [Device],
    network_id: &NetworkId,
) -> Result<BTreeMap<&'a DeviceId, &'a Device>, PlanError> {
    let active_devices = devices
        .iter()
        .filter(|device| &device.network_id == network_id && device.is_active())
        .collect::<Vec<_>>();
    if !has_unique_ids(&active_devices, |device| device.id.clone()) {
        return Err(PlanError::AmbiguousInput);
    }
    let devices = active_devices
        .iter()
        .map(|device| (&device.id, *device))
        .collect::<BTreeMap<_, _>>();
    for device in devices.values() {
        if devices
            .values()
            .any(|other| other.id != device.id && other.virtual_ipv4 == device.virtual_ipv4)
        {
            return Err(PlanError::AmbiguousInput);
        }
    }
    Ok(devices)
}

fn active_segments_by_id<'a>(
    segments: &'a [Segment],
    network_id: &NetworkId,
) -> Result<BTreeMap<&'a SegmentId, &'a Segment>, PlanError> {
    let active_segments = segments
        .iter()
        .filter(|segment| {
            &segment.network_id == network_id
                && segment.status == meshlet_domain::SegmentStatus::Active
        })
        .collect::<Vec<_>>();
    if !has_unique_ids(&active_segments, |segment| segment.id.clone()) {
        return Err(PlanError::AmbiguousInput);
    }
    let segments = active_segments
        .iter()
        .map(|segment| (&segment.id, *segment))
        .collect::<BTreeMap<_, _>>();
    Ok(segments)
}

fn published_objects<'a>(
    routes: &'a [LanRoute],
    aliases: &'a [AliasMapping],
    network_id: &NetworkId,
) -> Result<(Vec<&'a LanRoute>, Vec<&'a AliasMapping>), PlanError> {
    if routes.iter().any(|route| &route.network_id != network_id)
        || aliases.iter().any(|alias| &alias.network_id != network_id)
    {
        return Err(PlanError::ForeignObject);
    }
    let routes = routes
        .iter()
        .filter(|route| route.status == DesiredStateStatus::Applied)
        .collect();
    let aliases = aliases
        .iter()
        .filter(|alias| alias.status == DesiredStateStatus::Applied)
        .collect();
    Ok((routes, aliases))
}

/// Compile the full deterministic network plan without touching a platform backend.
#[allow(clippy::too_many_arguments)]
pub fn plan_network(
    network_id: NetworkId,
    overlay: Ipv4Cidr,
    devices: &[Device],
    segments: &[Segment],
    grants: &[SegmentGrant],
    routes: &[LanRoute],
    aliases: &[AliasMapping],
) -> Result<NetworkPlan, PlanError> {
    let server_conflicts = validate_network(
        &network_id,
        overlay,
        devices,
        segments,
        grants,
        routes,
        aliases,
        &[],
    );
    if server_conflicts
        .iter()
        .any(meshlet_domain::Conflict::is_blocking)
    {
        return Err(PlanError::NetworkConflicts(server_conflicts));
    }

    let devices = active_devices_by_id(devices, &network_id)?;
    let segments = active_segments_by_id(segments, &network_id)?;
    for device in devices.values() {
        if !overlay.contains(device.virtual_ipv4) {
            return Err(PlanError::DeviceOutsideOverlay(device.id.clone()));
        }
    }
    let (routes, aliases) = published_objects(routes, aliases, &network_id)?;
    for route in &routes {
        if !devices.contains_key(&&route.gateway_device_id) {
            return Err(PlanError::UnknownGateway(route.gateway_device_id.clone()));
        }
    }

    let aliases_by_route = aliases.iter().fold(
        BTreeMap::<meshlet_domain::LanRouteId, Vec<_>>::new(),
        |mut aliases, alias| {
            aliases
                .entry(alias.lan_route_id.clone())
                .or_default()
                .push(alias);
            aliases
        },
    );
    if aliases_by_route.values().any(|aliases| aliases.len() != 1) {
        return Err(PlanError::AmbiguousInput);
    }

    let device_values = devices
        .values()
        .map(|device| (*device).clone())
        .collect::<Vec<_>>();
    let owned_routes = routes
        .iter()
        .map(|route| (*route).clone())
        .collect::<Vec<_>>();
    let owned_aliases = aliases
        .iter()
        .map(|alias| (*alias).clone())
        .collect::<Vec<_>>();
    let mut hub_peers = hub_device_peers(overlay, &device_values, &owned_routes, &owned_aliases)
        .map_err(|_| PlanError::DeviceOutsideOverlay(DeviceId("unknown".into())))?;
    hub_peers.sort_by(|left, right| left.device_id.cmp(&right.device_id));

    let mut gateways = Vec::new();
    for (gateway_id, gateway) in &devices {
        let owned_routes = routes
            .iter()
            .filter(|route| &route.gateway_device_id == *gateway_id)
            .collect::<Vec<_>>();
        if owned_routes.is_empty() {
            continue;
        }
        let mut direct_routes = owned_routes
            .iter()
            .filter(|route| route.route_mode == RouteMode::Direct)
            .map(|route| route.destination_cidr)
            .collect::<Vec<_>>();
        let mut alias_routes = Vec::new();
        for route in owned_routes
            .iter()
            .filter(|route| route.route_mode == RouteMode::Alias)
        {
            let Some(alias) = aliases_by_route
                .get(&route.id)
                .and_then(|aliases| aliases.first())
            else {
                return Err(PlanError::AliasRouteAmbiguous(route.id.clone()));
            };
            alias_routes.push(AliasRoute {
                id: alias.id.clone(),
                lan_route_id: alias.lan_route_id.clone(),
                alias_cidr: alias.alias_cidr,
                target_cidr: alias.target_cidr,
                translation_mode: alias.translation_mode,
                snat_return_path: route.return_path_mode == ReturnPathMode::ControlledSnat,
            });
        }
        direct_routes.sort();
        direct_routes.dedup();
        alias_routes.sort_by(|left, right| {
            (&left.alias_cidr, &left.id).cmp(&(&right.alias_cidr, &right.id))
        });
        gateways.push(GatewayRoutePlan {
            device_id: (*gateway_id).clone(),
            virtual_address: gateway.virtual_ipv4,
            direct_routes,
            aliases: alias_routes,
        });
    }

    let mut device_plans = Vec::with_capacity(devices.len());
    for (device_id, device) in &devices {
        let segment = segments
            .get(&device.segment_id)
            .ok_or_else(|| PlanError::UnknownDeviceSegment((*device_id).clone()))?;
        let mut allowed_ips = vec![overlay];
        let mut planned_routes = Vec::new();
        for route in &routes {
            if &route.gateway_device_id == *device_id {
                continue;
            }
            let route_gateway = devices
                .get(&route.gateway_device_id)
                .ok_or_else(|| PlanError::UnknownGateway(route.gateway_device_id.clone()))?;
            let Some(gateway_segment) = segments.get(&route_gateway.segment_id) else {
                return Err(PlanError::UnknownDeviceSegment(route_gateway.id.clone()));
            };
            let same_segment = gateway_segment.id == segment.id;
            let authorized = grants.iter().any(|grant| {
                grant.status == SegmentGrantStatus::Applied
                    && grant.source_segment_id == segment.id
                    && grant.destination_segment_id == gateway_segment.id
            });
            if !same_segment && !authorized {
                continue;
            }
            let destinations = match route.route_mode {
                RouteMode::Direct => vec![route.destination_cidr],
                RouteMode::Alias => aliases_by_route
                    .get(&route.id)
                    .map(|aliases| aliases.iter().map(|alias| alias.alias_cidr).collect())
                    .unwrap_or_default(),
            };
            for destination in destinations {
                allowed_ips.push(destination);
                planned_routes.push(Route {
                    destination,
                    gateway: route_gateway.virtual_ipv4,
                });
            }
        }
        allowed_ips.sort();
        allowed_ips.dedup();
        planned_routes.sort_by(|left, right| {
            (&left.destination, left.gateway).cmp(&(&right.destination, right.gateway))
        });
        planned_routes.dedup();
        device_plans.push(DeviceRoutePlan {
            device_id: (*device_id).clone(),
            virtual_address: device.virtual_ipv4,
            segment_id: segment.id.clone(),
            allowed_ips,
            routes: planned_routes,
        });
    }

    gateways.sort_by(|left, right| left.device_id.cmp(&right.device_id));
    device_plans.sort_by(|left, right| left.device_id.cmp(&right.device_id));
    Ok(NetworkPlan {
        network_id,
        overlay,
        hub_peers,
        gateways,
        devices: device_plans,
    })
}
