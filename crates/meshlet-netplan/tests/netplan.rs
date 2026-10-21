use meshlet_domain::{
    AliasMapping, AliasMappingId, ConflictCode, DesiredStateStatus, Device, DeviceId, DeviceStatus,
    Ipam, Ipv4Cidr, LanRoute, LanRouteId, NetworkId, Platform, ReturnPathMode, RouteMode, Segment,
    SegmentGrant, SegmentGrantStatus, SegmentId, SegmentStatus, TranslationMode,
};
use meshlet_netplan::{
    analyze_network_conflicts, plan_network, validate_network, PlanError, Route,
};

type PlanFixture = (
    Vec<Device>,
    Vec<Segment>,
    Vec<SegmentGrant>,
    Vec<LanRoute>,
    Vec<AliasMapping>,
);

fn route(id: &str, gateway: &str, destination: &str, mode: RouteMode) -> LanRoute {
    LanRoute {
        id: LanRouteId(id.into()),
        network_id: NetworkId("net".into()),
        gateway_device_id: DeviceId(gateway.into()),
        destination_cidr: destination.parse().unwrap(),
        route_mode: mode,
        return_path_mode: ReturnPathMode::ControlledSnat,
        status: DesiredStateStatus::Applied,
        created_at: "2026-10-21T00:00:00Z".into(),
    }
}

fn alias_mapping(
    id: &str,
    route_id: &str,
    alias_cidr: &str,
    target: &str,
    status: DesiredStateStatus,
) -> AliasMapping {
    let mut alias = AliasMapping::new(
        AliasMappingId(id.into()),
        NetworkId("net".into()),
        LanRouteId(route_id.into()),
        alias_cidr.parse().unwrap(),
        target.parse().unwrap(),
        TranslationMode::DnatSnat,
    )
    .unwrap();
    alias.status = status;
    alias
}

fn alias(id: &str, route_id: &str, alias_cidr: &str, target: &str) -> AliasMapping {
    alias_mapping(
        id,
        route_id,
        alias_cidr,
        target,
        DesiredStateStatus::Applied,
    )
}

fn network_id() -> NetworkId {
    NetworkId("net".into())
}
const OVERLAY: &str = "10.240.0.0/16";

fn device(id: &str, address: &str, segment: &str) -> Device {
    Device {
        id: DeviceId(id.into()),
        network_id: network_id(),
        name: id.into(),
        virtual_ipv4: address.parse().unwrap(),
        public_key: format!("key-{id}"),
        platform: Platform::Linux,
        status: DeviceStatus::Active,
        last_seen_at: None,
        last_handshake_at: None,
        last_report_at: None,
        dataplane_evidence: None,
        created_at: "2026-10-21T00:00:00Z".into(),
        approved_at: None,
        segment_id: SegmentId(segment.into()),
        revoked_at: None,
    }
}

fn segment(id: &str, name: &str, cidr: &str) -> Segment {
    Segment {
        id: SegmentId(id.into()),
        network_id: network_id(),
        name: name.into(),
        cidr: cidr.parse().unwrap(),
        status: SegmentStatus::Active,
        created_at: "2026-10-21T00:00:00Z".into(),
    }
}

fn grant_with_status(
    id: &str,
    source: &str,
    destination: &str,
    status: SegmentGrantStatus,
) -> SegmentGrant {
    SegmentGrant {
        id: meshlet_domain::SegmentGrantId(id.into()),
        network_id: network_id(),
        source_segment_id: SegmentId(source.into()),
        destination_segment_id: SegmentId(destination.into()),
        status,
        created_at: "2026-10-21T00:00:00Z".into(),
        revoked_at: None,
    }
}

fn grant(id: &str, source: &str, destination: &str) -> SegmentGrant {
    grant_with_status(id, source, destination, SegmentGrantStatus::Applied)
}

fn fixture() -> PlanFixture {
    (
        vec![
            device("client-a", "10.240.0.10", "seg-default"),
            device("client-b", "10.240.8.2", "seg-beta"),
            device("gateway-a", "10.240.1.20", "seg-alpha"),
            device("gateway-z", "10.240.8.30", "seg-beta"),
        ],
        vec![
            segment("seg-default", "default", "10.240.0.0/24"),
            segment("seg-alpha", "alpha", "10.240.1.0/24"),
            segment("seg-beta", "beta", "10.240.8.0/24"),
        ],
        vec![grant("grant-a", "seg-default", "seg-alpha")],
        vec![
            route("route-a", "gateway-a", "192.168.10.0/24", RouteMode::Direct),
            route("route-z", "gateway-z", "192.168.20.0/24", RouteMode::Direct),
            route(
                "route-collide-a",
                "gateway-a",
                "192.168.1.0/24",
                RouteMode::Alias,
            ),
            route(
                "route-collide-z",
                "gateway-z",
                "192.168.1.0/24",
                RouteMode::Alias,
            ),
        ],
        vec![
            alias(
                "alias-collide-z",
                "route-collide-z",
                "10.241.2.0/24",
                "192.168.1.0/24",
            ),
            alias(
                "alias-collide-a",
                "route-collide-a",
                "10.241.1.0/24",
                "192.168.1.0/24",
            ),
        ],
    )
}

fn shuffled_plan_inputs() -> PlanFixture {
    let (devices, segments, grants, routes, aliases) = fixture();
    (
        devices.into_iter().rev().collect(),
        segments.into_iter().rev().collect(),
        grants,
        routes.into_iter().rev().collect(),
        aliases.into_iter().rev().collect(),
    )
}

#[test]
fn pending_alias_mappings_are_excluded_and_fixture_objects_are_published() {
    let (_, segments, grants, routes, aliases) = fixture();

    assert!(aliases
        .iter()
        .all(|alias| alias.status == DesiredStateStatus::Applied));
    assert!(routes
        .iter()
        .all(|route| route.status == DesiredStateStatus::Applied));
    assert!(segments
        .iter()
        .all(|segment| segment.status == SegmentStatus::Active));
    assert!(grants
        .iter()
        .all(|grant| grant.status == SegmentGrantStatus::Applied));

    let pending_aliases = [
        alias_mapping(
            "alias-pending",
            "route-a",
            "10.241.1.0/24",
            "192.168.10.0/24",
            DesiredStateStatus::Pending,
        ),
        alias_mapping(
            "alias-applied",
            "route-a",
            "10.241.1.0/24",
            "192.168.10.0/24",
            DesiredStateStatus::Applied,
        ),
    ];
    let devices = [device("gateway-a", "10.240.1.20", "seg-alpha")];
    let segments = [segment("seg-alpha", "alpha", "10.240.1.0/24")];
    let routes = [route(
        "route-a",
        "gateway-a",
        "192.168.10.0/24",
        RouteMode::Alias,
    )];
    let conflicts = validate_network(
        &network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &segments,
        &[],
        &routes,
        &pending_aliases,
        &[],
    );

    assert!(conflicts.is_empty());
    let plan = plan_network(
        network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &segments,
        &[],
        &routes,
        &pending_aliases,
    )
    .unwrap();
    let gateway = plan.gateways.first().unwrap();
    assert_eq!(gateway.aliases.len(), 1);
    assert_eq!(
        gateway.aliases[0].id,
        AliasMappingId("alias-applied".into())
    );
}

#[test]
fn stable_ipam_allocates_lowest_free_addresses_independent_of_input_order() {
    let overlay: Ipv4Cidr = OVERLAY.parse().unwrap();
    let mut first = Ipam::new(overlay, "10.240.0.1".parse().unwrap()).unwrap();
    first.reserve("10.240.0.3".parse().unwrap()).unwrap();

    let identities = [
        DeviceId("z".into()),
        DeviceId("a".into()),
        DeviceId("m".into()),
    ];
    let reverse = identities.iter().rev().cloned().collect::<Vec<_>>();
    let addresses = [
        first.clone().allocate_by_identity(&identities).unwrap(),
        first.clone().allocate_by_identity(&reverse).unwrap(),
    ];

    assert_eq!(addresses[0], addresses[1]);
    assert_eq!(
        addresses[0],
        vec![
            (
                DeviceId("a".into()),
                std::net::Ipv4Addr::from([10, 240, 0, 2])
            ),
            (
                DeviceId("m".into()),
                std::net::Ipv4Addr::from([10, 240, 0, 4])
            ),
            (
                DeviceId("z".into()),
                std::net::Ipv4Addr::from([10, 240, 0, 5])
            ),
        ]
    );
}

#[test]
fn conflicting_segment_policies_are_reported_before_gateway_selection() {
    let (devices, segments, grants, routes, aliases) = fixture();
    let conflicting_segments = vec![segment("seg-alpha-2", "alpha-2", "10.240.1.0/25")];
    let mut all_segments = segments;
    all_segments.extend(conflicting_segments);
    let mut reversed_segments = all_segments.clone();
    reversed_segments.reverse();

    let forward = validate_network(
        &network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &all_segments,
        &grants,
        &routes,
        &aliases,
        &[],
    );
    let reverse = validate_network(
        &network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &reversed_segments,
        &grants,
        &routes,
        &aliases,
        &[],
    );

    assert_eq!(forward, reverse);
    assert!(forward
        .iter()
        .any(|conflict| conflict.code == ConflictCode::SegmentSegmentOverlap));
}

#[test]
fn overlapping_alias_space_is_rejected_without_favoring_input_order() {
    let routes = [
        route("route-a", "gateway-a", "192.168.10.0/24", RouteMode::Alias),
        route("route-z", "gateway-z", "192.168.20.0/24", RouteMode::Alias),
    ];
    let forward_aliases = [
        alias("alias-a", "route-a", "10.241.0.0/24", "192.168.10.0/24"),
        alias("alias-z", "route-z", "10.241.0.0/24", "192.168.20.0/24"),
    ];
    let reverse_aliases = [forward_aliases[1].clone(), forward_aliases[0].clone()];
    let overlay: Ipv4Cidr = OVERLAY.parse().unwrap();

    let forward = analyze_network_conflicts(overlay, &forward_aliases, &routes, &[], &[]);
    let reverse = analyze_network_conflicts(overlay, &reverse_aliases, &routes, &[], &[]);

    assert_eq!(forward, reverse);
    assert!(forward
        .iter()
        .any(|conflict| conflict.code == ConflictCode::AliasAliasOverlap));
}

#[test]
fn same_gateway_cannot_host_two_alias_routes_for_one_real_prefix() {
    let routes = [
        route("route-a", "gateway-a", "192.168.1.0/24", RouteMode::Alias),
        route("route-a-2", "gateway-a", "192.168.1.0/24", RouteMode::Alias),
    ];
    let forward_aliases = [
        alias("alias-a", "route-a", "10.241.1.0/24", "192.168.1.0/24"),
        alias("alias-a-2", "route-a-2", "10.241.2.0/24", "192.168.1.0/24"),
    ];
    let reverse_routes = [routes[1].clone(), routes[0].clone()];
    let reverse_aliases = [forward_aliases[1].clone(), forward_aliases[0].clone()];
    let overlay: Ipv4Cidr = OVERLAY.parse().unwrap();

    let forward = analyze_network_conflicts(overlay, &forward_aliases, &routes, &[], &[]);
    let reverse = analyze_network_conflicts(overlay, &reverse_aliases, &reverse_routes, &[], &[]);

    assert_eq!(forward, reverse);
    assert!(forward
        .iter()
        .any(|conflict| conflict.code == ConflictCode::LanRouteConflict));
}

#[test]
fn hub_plan_is_identical_after_shuffling_creation_order() {
    let (devices, segments, grants, routes, aliases) = fixture();
    let forward = plan_network(
        network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &segments,
        &grants,
        &routes,
        &aliases,
    )
    .unwrap();
    let (devices, segments, grants, routes, aliases) = shuffled_plan_inputs();
    let reverse = plan_network(
        network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &segments,
        &grants,
        &routes,
        &aliases,
    )
    .unwrap();

    assert_eq!(forward, reverse);
    assert!(forward
        .gateways
        .windows(2)
        .all(|pair| pair[0].device_id < pair[1].device_id));
    assert!(forward
        .devices
        .windows(2)
        .all(|pair| pair[0].device_id < pair[1].device_id));
    assert!(forward
        .hub_peers
        .windows(2)
        .all(|pair| pair[0].device_id < pair[1].device_id));
}

#[test]
fn unknown_segment_grant_endpoints_are_rejected() {
    let (devices, segments, grants, routes, aliases) = fixture();
    let unknown_endpoints = [
        grant("grant-source", "seg-missing", "seg-alpha"),
        grant("grant-destination", "seg-default", "seg-missing"),
        grant(
            "grant-both",
            "seg-missing-source",
            "seg-missing-destination",
        ),
    ];
    let mut all_grants = grants;
    all_grants.extend(unknown_endpoints);

    let conflicts = validate_network(
        &network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &segments,
        &all_grants,
        &routes,
        &aliases,
        &[],
    );

    assert_eq!(
        conflicts
            .iter()
            .filter(|conflict| conflict.code == ConflictCode::UnknownSegmentGrantEndpoint)
            .count(),
        3
    );

    for grant_id in ["grant-source", "grant-destination", "grant-both"] {
        assert!(conflicts.iter().any(|conflict| {
            conflict.code == ConflictCode::UnknownSegmentGrantEndpoint
                && conflict.detail.contains(grant_id)
        }));
    }
}

#[test]
fn duplicate_grant_ids_and_applied_pairs_are_ambiguous() {
    let (devices, segments, _, routes, aliases) = fixture();
    let duplicate_ids = [
        grant("grant-duplicate", "seg-default", "seg-alpha"),
        grant("grant-duplicate", "seg-default", "seg-beta"),
    ];
    let id_conflicts = validate_network(
        &network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &segments,
        &duplicate_ids,
        &routes,
        &aliases,
        &[],
    );
    assert!(id_conflicts
        .iter()
        .any(|conflict| conflict.code == ConflictCode::AmbiguousInput
            && conflict.detail.contains("unique IDs")));

    let duplicate_pairs = [
        grant("grant-a", "seg-default", "seg-alpha"),
        grant("grant-duplicate", "seg-default", "seg-alpha"),
    ];
    let pair_conflicts = validate_network(
        &network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &segments,
        &duplicate_pairs,
        &routes,
        &aliases,
        &[],
    );
    assert!(pair_conflicts
        .iter()
        .any(|conflict| conflict.code == ConflictCode::AmbiguousInput
            && conflict.detail.contains("unique source-destination pairs")));

    let pending_duplicate_pair = [
        grant_with_status(
            "grant-pending-a",
            "seg-default",
            "seg-alpha",
            SegmentGrantStatus::Pending,
        ),
        grant_with_status(
            "grant-pending-b",
            "seg-default",
            "seg-alpha",
            SegmentGrantStatus::Pending,
        ),
    ];
    let pending_pair_conflicts = validate_network(
        &network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &segments,
        &pending_duplicate_pair,
        &routes,
        &aliases,
        &[],
    );
    assert!(!pending_pair_conflicts
        .iter()
        .any(|conflict| conflict.code == ConflictCode::AmbiguousInput
            && conflict.detail.contains("unique source-destination pairs")));
}

#[test]
fn global_conflict_set_and_plan_error_are_order_independent() {
    let (devices, segments, grants, mut routes, aliases) = fixture();
    routes.push(route(
        "route-direct-conflict",
        "gateway-a",
        "192.168.1.0/24",
        RouteMode::Direct,
    ));
    let overlay: meshlet_domain::Ipv4Cidr = OVERLAY.parse().unwrap();
    let mut routes_reversed = routes.clone();
    routes_reversed.reverse();
    let forward = validate_network(
        &network_id(),
        overlay,
        &devices,
        &segments,
        &grants,
        &routes,
        &aliases,
        &["192.168.0.0/16".parse().unwrap()],
    );
    let reverse = validate_network(
        &network_id(),
        overlay,
        &devices,
        &segments,
        &grants,
        &routes_reversed,
        &aliases,
        &["192.168.0.0/16".parse().unwrap()],
    );
    assert_eq!(forward, reverse);
    assert!(forward
        .iter()
        .any(|conflict| conflict.code == ConflictCode::LanRouteConflict));
    assert_eq!(forward.len(), 2);

    let forward_error = plan_network(
        network_id(),
        overlay,
        &devices,
        &segments,
        &grants,
        &routes,
        &aliases,
    )
    .unwrap_err();
    let reverse_error = plan_network(
        network_id(),
        overlay,
        &devices,
        &segments,
        &grants,
        &routes_reversed,
        &aliases,
    )
    .unwrap_err();
    assert_eq!(
        forward_error,
        PlanError::NetworkConflicts(analyze_network_conflicts(
            overlay,
            &aliases,
            &routes,
            &segments,
            &[]
        ))
    );
    assert_eq!(forward_error, reverse_error);
}

#[test]
fn segment_policy_limits_routes_but_gateway_identity_is_stable() {
    let (devices, segments, grants, routes, aliases) = fixture();
    let plan = plan_network(
        network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &segments,
        &grants,
        &routes,
        &aliases,
    )
    .unwrap();
    let alpha_gateway = plan
        .gateways
        .iter()
        .find(|gateway| gateway.device_id == DeviceId("gateway-a".into()))
        .unwrap();
    assert_eq!(
        alpha_gateway.direct_routes,
        vec!["192.168.10.0/24".parse().unwrap()]
    );

    let default_client = plan
        .devices
        .iter()
        .find(|device| device.device_id == DeviceId("client-a".into()))
        .unwrap();
    let route_gateways = default_client
        .routes
        .iter()
        .map(|route| route.gateway)
        .collect::<Vec<_>>();
    assert!(route_gateways.contains(&"10.240.1.20".parse().unwrap()));
    assert!(!route_gateways.contains(&"10.240.8.30".parse().unwrap()));

    let beta_client = plan
        .devices
        .iter()
        .find(|device| device.device_id == DeviceId("client-b".into()))
        .unwrap();
    assert!(beta_client
        .routes
        .iter()
        .all(|route| route.gateway == "10.240.8.30".parse::<std::net::Ipv4Addr>().unwrap()));
}

#[test]
fn alias_device_routes_use_alias_space_and_stable_order() {
    let routes = [
        route("route-a", "gateway-a", "192.168.10.0/24", RouteMode::Alias),
        route("route-z", "gateway-z", "192.168.20.0/24", RouteMode::Alias),
    ];
    let aliases = [
        alias("alias-z", "route-z", "10.241.2.0/24", "192.168.20.0/24"),
        alias("alias-a", "route-a", "10.241.1.0/24", "192.168.10.0/24"),
    ];
    let grants = [
        grant("grant-alpha", "seg-default", "seg-alpha"),
        grant("grant-beta", "seg-default", "seg-beta"),
    ];
    let mut devices = fixture().0;
    devices.retain(|device| {
        device.id == DeviceId("client-a".into())
            || device.id == DeviceId("gateway-a".into())
            || device.id == DeviceId("gateway-z".into())
    });
    let mut segments = fixture().1;
    segments.retain(|segment| {
        segment.id == SegmentId("seg-default".into())
            || segment.id == SegmentId("seg-alpha".into())
            || segment.id == SegmentId("seg-beta".into())
    });
    let forward = plan_network(
        network_id(),
        OVERLAY.parse().unwrap(),
        &devices,
        &segments,
        &grants,
        &routes,
        &aliases,
    )
    .unwrap();
    let reverse = plan_network(
        network_id(),
        OVERLAY.parse().unwrap(),
        &[devices[2].clone(), devices[0].clone(), devices[1].clone()],
        &segments,
        &grants,
        &[routes[1].clone(), routes[0].clone()],
        &[aliases[1].clone(), aliases[0].clone()],
    )
    .unwrap();
    assert_eq!(forward, reverse);
    let client = forward
        .devices
        .iter()
        .find(|device| device.device_id == DeviceId("client-a".into()))
        .unwrap();
    assert_eq!(
        client.routes,
        vec![
            Route {
                destination: "10.241.1.0/24".parse().unwrap(),
                gateway: "10.240.1.20".parse().unwrap(),
            },
            Route {
                destination: "10.241.2.0/24".parse().unwrap(),
                gateway: "10.240.8.30".parse().unwrap(),
            },
        ]
    );
}

#[test]
fn conflicting_overlays_reject_device_peer_plans() {
    let (mut devices, segments, grants, routes, aliases) = fixture();
    devices.retain(|device| device.id == DeviceId("client-a".into()));
    let result = plan_network(
        network_id(),
        "10.0.0.0/8".parse().unwrap(),
        &devices,
        &segments,
        &grants,
        &routes,
        &aliases,
    );
    assert!(matches!(
        result,
        Err(PlanError::NetworkConflicts(_)) | Err(PlanError::DeviceOutsideOverlay(_))
    ));
}
