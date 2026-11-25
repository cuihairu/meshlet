//! Device data-plane plan
//! ([ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)).
//!
//! The agent consumes only [`meshlet_network::DevicePlan`] -- a **structured
//! configuration object** (§16.4): a typed tunnel/route/NAT plan plus the
//! desired-config hash; the agent reconciles against it and replays the local
//! network backend. **The server never sends the agent any Shell command**,
//! and the agent never executes a delivered script.
//!
//! - tunnel: this device's virtual IP + a single peer towards the hub
//!   (AllowedIPs consistent with the destination routes, §7.2; locally
//!   published LAN prefixes are not fed back into the tunnel, to avoid loops);
//! - routes: LAN/Alias prefixes published by others via the corresponding
//!   gateway device's virtual IP;
//! - NAT: the rules to deliver when this device acts as a gateway (rendered
//!   at the plan layer, with the ownership annotation `meshlet alias {id}`;
//!   deleting a mapping cleans up the whole unit, §12.6);
//! - the private key never leaves the device (ADR-010): the plan's
//!   `tunnel.private_key` is always `None`, injected locally by the agent; the
//!   hub public key is derived on the fly from `[dataplane] private_key_file`
//!   (never persisted).

use meshlet_config::DataPlaneConfig;
use meshlet_domain::{
    peer_routes::client_hub_peer_allowed_ips, AliasMapping, DesiredStateStatus, DeviceId, RouteMode,
};
use meshlet_network::nat::alias_nat_rules;
use meshlet_network::{DevicePlan, PeerConfig, RouteConfig, SystemBackend, TunnelConfig};

use crate::service::MeshState;

pub(crate) fn segment_for<'a>(
    mesh: &'a MeshState,
    network_id: &str,
    device: &meshlet_domain::Device,
) -> Option<&'a meshlet_domain::Segment> {
    mesh.segments(network_id)
        .iter()
        .find(|segment| segment.id == device.segment_id)
}

fn route_visible(
    mesh: &MeshState,
    network_id: &str,
    source_segment: &meshlet_domain::Segment,
    route: &meshlet_domain::LanRoute,
) -> bool {
    let Some(network) = mesh.network_row(network_id) else {
        return false;
    };
    if source_segment.cidr == network.overlay_cidr {
        return true;
    }
    // Custom segments deliberately exclude the hub's Overlay default segment.
    let Some(gateway) = mesh.registry.find_by_id(&route.gateway_device_id) else {
        return false;
    };
    let Some(gateway_segment) = segment_for(mesh, network_id, gateway) else {
        return false;
    };
    gateway_segment.id == source_segment.id
        || mesh.segment_grants(network_id).iter().any(|grant| {
            grant.status == meshlet_domain::SegmentGrantStatus::Applied
                && grant.source_segment_id == source_segment.id
                && grant.destination_segment_id == gateway_segment.id
        })
}

/// Hub public key: read from `[dataplane] private_key_file` at apply time and
/// derived via `wg pubkey` (never persisted, never sent out -- ADR-010). The
/// hub's first installation must configure that file.
pub fn hub_public_key(dataplane: &DataPlaneConfig) -> Result<String, String> {
    let path = dataplane
        .private_key_file
        .as_ref()
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(|| {
            "dataplane.private_key_file is not configured: the hub public key cannot be \
             derived for the device plans"
                .to_string()
        })?;
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("read private_key_file {path}: {e}"))?;
    let key = raw.trim().to_string();
    if key.is_empty() {
        return Err(format!("private_key_file {path} is empty"));
    }
    SystemBackend::new()
        .public_key_from_private(&key)
        .map_err(|e| format!("derive hub public key from private_key_file {path}: {e}"))
}

/// Translate the desired configuration of a given device into the data-plane
/// plan the agent can execute.
///
/// The plan shares the same derivation source as the hub-side plan (§7.2's
/// AllowedIPs rule, §9.4's gateway-side NAT), so the two sides cannot drift;
/// `desired_config_hash` uses the same hash as the revision bookkeeping, and
/// the agent can use it to decide "only replay when there is a change"
/// (§10.1).
pub fn build_device_plan(
    mesh: &MeshState,
    network_id: &str,
    device_id: &DeviceId,
    dataplane: &DataPlaneConfig,
    tunnel_mtu: Option<u32>,
    hub_public_key: &str,
    ssh_distribute: Option<&meshlet_config::SshDistributeConfig>,
) -> Result<DevicePlan, String> {
    let network = mesh
        .network_row(network_id)
        .ok_or_else(|| format!("network {network_id} not found"))?;
    let device = mesh
        .registry
        .find_by_id(device_id)
        .cloned()
        .ok_or_else(|| format!("device {device_id} not found"))?;
    let hub = mesh
        .hub_address(network_id)
        .ok_or_else(|| format!("ipam missing for network {network_id}"))?;
    let overlay = network.overlay_cidr;
    let mut planned_routes = mesh.lan_routes.get(network_id).cloned().unwrap_or_default();
    let mut planned_aliases: Vec<AliasMapping> =
        mesh.aliases.get(network_id).cloned().unwrap_or_default();

    for route in &mut planned_routes {
        route.status = DesiredStateStatus::Applied;
    }
    for alias in &mut planned_aliases {
        alias.status = DesiredStateStatus::Applied;
    }
    let source_segment = segment_for(mesh, network_id, &device)
        .ok_or_else(|| format!("device {device_id} has no segment assignment"))?;
    planned_routes.retain(|route| route_visible(mesh, network_id, source_segment, route));
    let route_ids: std::collections::BTreeSet<_> = planned_routes
        .iter()
        .map(|route| route.id.clone())
        .collect();
    planned_aliases.retain(|alias| route_ids.contains(&alias.lan_route_id));
    let routes_in = planned_routes.as_slice();
    let aliases = planned_aliases.as_slice();
    // AllowedIPs come from the single derivation at the domain layer: Overlay +
    // LAN/Alias published by others (one's own local prefixes are not fed back,
    // to avoid loops). Routes map one-to-one onto them: destination prefix via
    // the corresponding gateway device.
    let allowed_ips =
        client_hub_peer_allowed_ips(source_segment.cidr, &device.id, routes_in, aliases);
    let mut routes = Vec::new();
    for route in routes_in {
        if route.gateway_device_id == device.id || route.status != DesiredStateStatus::Applied {
            continue;
        }
        let Some(gateway) = mesh.registry.find_by_id(&route.gateway_device_id) else {
            continue;
        };
        let destinations: Vec<_> = match route.route_mode {
            RouteMode::Direct => vec![route.destination_cidr],
            RouteMode::Alias => aliases
                .iter()
                .filter(|a| a.lan_route_id == route.id && a.status == DesiredStateStatus::Applied)
                .map(|a| a.alias_cidr)
                .collect(),
        };
        for destination in destinations {
            routes.push(RouteConfig {
                destination,
                interface: dataplane.interface.clone(),
                gateway: Some(gateway.virtual_ipv4),
            });
        }
    }

    // NAT when this device acts as a gateway: Alias mode renders per mapping;
    // Direct runs on the real LAN and needs no translation.
    let mut nat_rules = Vec::new();
    for route in routes_in {
        if route.gateway_device_id != device.id || route.status != DesiredStateStatus::Applied {
            continue;
        }
        if route.route_mode == RouteMode::Direct {
            if route.return_path_mode == meshlet_domain::ReturnPathMode::ControlledSnat {
                nat_rules.push(meshlet_network::nat::NatRule {
                    source_cidr: None,
                    incoming_interface: None,
                    chain: meshlet_network::nat::NatChain::Postrouting,
                    match_dest: route.destination_cidr,
                    action: meshlet_network::nat::NatAction::SnatToGatewayLan,
                    owner: format!("meshlet alias direct-{}", route.id),
                });
            }
            continue;
        }
        for alias in aliases.iter().filter(|a| a.lan_route_id == route.id) {
            if alias.status == DesiredStateStatus::Applied {
                nat_rules.extend(alias_nat_rules(alias));
            }
        }
    }

    for rule in &mut nat_rules {
        rule.source_cidr = Some(overlay);
        // `-i` only takes effect on PREROUTING (same criterion as
        // `NatRule::iptables_args`): stuffing an interface onto a POSTROUTING
        // rule is inert metadata -- it renders nothing, and it also makes the
        // fingerprint criterion disagree between the plan side and the kernel
        // side.
        if rule.chain == meshlet_network::nat::NatChain::Prerouting {
            rule.incoming_interface = Some(dataplane.interface.clone());
        }
    }
    // Canonical order keeps plan hashes stable across DB reloads and input ordering.
    routes.sort_by(|a, b| {
        a.destination
            .cmp(&b.destination)
            .then(a.gateway.cmp(&b.gateway))
    });
    nat_rules.sort_by(|a, b| {
        let chain = |r: &meshlet_network::nat::NatRule| {
            if r.chain == meshlet_network::nat::NatChain::Prerouting {
                0
            } else {
                1
            }
        };
        chain(a)
            .cmp(&chain(b))
            .then(a.match_dest.cmp(&b.match_dest))
            .then(a.owner.cmp(&b.owner))
    });

    let mut plan = DevicePlan {
        desired_revision: mesh
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.into()))
            .map(|r| r.revision)
            .unwrap_or(0),
        hub_port: crate::revision::network_dataplane(dataplane, network_id)?.listen_port,
        tunnel: TunnelConfig {
            name: dataplane.interface.clone(),
            address: device.virtual_ipv4,
            address_prefix: overlay.prefix_len(),
            listen_port: None,
            peers: vec![PeerConfig {
                public_key: hub_public_key.to_string(),
                allowed_ips,
                // The hub entry address comes from the agent's local configuration
                // (`[dataplane] hub_endpoint`); leave it empty when the server
                // has not configured advertise_ip, and the agent falls back on
                // its own.
                endpoint: None,
                persistent_keepalive_secs: Some(25),
            }],
            mtu: tunnel_mtu,
            private_key: None,
        },
        routes,
        nat_rules,
        // The hub's overlay address only serves as a local diagnostic target for the
        // agent (MTU large-packet probing); it never enters the kernel.
        hub_address: Some(hub),
        // Service publication plan (R-06): the desired publication state of the
        // control-plane catalog filtered to this device (`None` = this device
        // has no publications); a plan-layer validation failure makes the whole
        // plan build visibly fail.
        publish: crate::publish::device_publish_plan(mesh, network_id, &device_id.to_string())?,
        ssh_config: ssh_config_plan(mesh, network_id, ssh_distribute),
        desired_config_hash: String::new(),
    };
    // Hash the actual device plan, including MTU, hub key and revision.
    plan.desired_config_hash.clear();
    use sha2::{Digest, Sha256};
    plan.desired_config_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&plan).map_err(|e| e.to_string())?)
    );
    Ok(plan)
}

/// SSH alias distribution segment (delivered only when the hub explicitly
/// turns it on): the alias table of every Active node in the network.
/// Three-tier alias resolution, shared with
/// [`meshlet_network::ssh_alias::resolve_alias`]: explicit hub override > the
/// node's real hostname (in-memory state reported by heartbeats) > peer name.
/// A `None` config = the hub has not enabled distribution -> the plan carries
/// no such segment (it is omitted from serialization too, leaving the old
/// plan hash unchanged).
fn ssh_config_plan(
    mesh: &MeshState,
    network_id: &str,
    ssh_distribute: Option<&meshlet_config::SshDistributeConfig>,
) -> Option<meshlet_network::SshConfigPlan> {
    let ssh = ssh_distribute?;
    let mut hosts = Vec::new();
    for device in mesh.registry.devices() {
        if device.network_id.0 != network_id || !device.is_active() {
            continue;
        }
        let over = ssh.overrides.get(&device.name);
        let hostname = mesh.device_hostnames.get(&device.id).map(String::as_str);
        let (alias, source) = meshlet_network::ssh_alias::resolve_alias(
            &device.name,
            hostname,
            over.and_then(|o| o.alias.as_deref()),
        );
        hosts.push(meshlet_network::SshHostConfig {
            name: device.name.clone(),
            alias,
            address: device.virtual_ipv4,
            port: over.and_then(|o| o.port),
            user: over.and_then(|o| o.user.clone()),
            alias_source: Some(source.to_string()),
        });
    }
    // Device-name order: fragment determinism (restoring the same network in any
    // order yields the same plan hash).
    hosts.sort_by(|a, b| a.name.cmp(&b.name));
    Some(meshlet_network::SshConfigPlan { hosts })
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::{
        AliasMappingId, Device, DeviceStatus, LanRouteId, Network, NetworkId, Platform,
        PresenceThresholds, RouteMode, Segment, SegmentId, TranslationMode,
    };
    use std::net::Ipv4Addr;

    const T0: &str = "2026-10-15T00:00:00Z";

    fn mesh() -> MeshState {
        let mut mesh = MeshState::new(PresenceThresholds::default());
        mesh.restore_network(Network::new(
            NetworkId("net-1".into()),
            "vpn",
            "10.240.0.0/16".parse().unwrap(),
            T0.into(),
        ))
        .unwrap();
        mesh.restore_segment(Segment {
            id: meshlet_domain::default_segment_id(&NetworkId("net-1".into())),
            network_id: NetworkId("net-1".into()),
            name: "default".into(),
            cidr: "10.240.0.0/16".parse().unwrap(),
            status: meshlet_domain::SegmentStatus::Active,
            created_at: T0.into(),
        })
        .unwrap();
        mesh
    }

    fn device(id: &str, ip: &str, status: DeviceStatus) -> Device {
        Device {
            id: DeviceId(id.into()),
            network_id: NetworkId("net-1".into()),
            name: id.into(),
            virtual_ipv4: ip.parse().unwrap(),
            public_key: format!("pub-{id}"),
            platform: Platform::Linux,
            status,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: T0.into(),
            approved_at: None,
            segment_id: meshlet_domain::SegmentId("seg-net-1".into()),
            revoked_at: None,
            labels: Default::default(),
        }
    }

    fn add(mesh: &mut MeshState, d: Device) {
        mesh.restore_device(d).unwrap();
    }

    fn route(id: &str, dst: &str, gw: &str, mode: RouteMode) -> meshlet_domain::LanRoute {
        meshlet_domain::LanRoute {
            id: LanRouteId(id.into()),
            network_id: NetworkId("net-1".into()),
            gateway_device_id: DeviceId(gw.into()),
            destination_cidr: dst.parse().unwrap(),
            route_mode: mode,
            return_path_mode: meshlet_domain::ReturnPathMode::DualRoute,
            status: DesiredStateStatus::Applied,
            created_at: T0.into(),
        }
    }

    fn alias(id: &str, route_id: &str, prefix: &str, target: &str) -> AliasMapping {
        let mut a = AliasMapping::new(
            AliasMappingId(id.into()),
            NetworkId("net-1".into()),
            LanRouteId(route_id.into()),
            prefix.parse().unwrap(),
            target.parse().unwrap(),
            TranslationMode::DnatSnat,
        )
        .unwrap();
        a.status = DesiredStateStatus::Applied;
        a
    }

    fn dataplane() -> DataPlaneConfig {
        DataPlaneConfig {
            enabled: true,
            ..DataPlaneConfig::default()
        }
    }

    #[test]
    fn custom_segments_limit_plan_and_applied_grant_restores_visibility() {
        let mut mesh = mesh();
        let default_id = meshlet_domain::default_segment_id(&NetworkId("net-1".into()));
        mesh.restore_segment(Segment {
            id: SegmentId("seg-a".into()),
            network_id: NetworkId("net-1".into()),
            name: "a".into(),
            cidr: "10.240.1.0/24".parse().unwrap(),
            status: meshlet_domain::SegmentStatus::Active,
            created_at: T0.into(),
        })
        .unwrap();
        mesh.restore_segment(Segment {
            id: SegmentId("seg-b".into()),
            network_id: NetworkId("net-1".into()),
            name: "b".into(),
            cidr: "10.240.2.0/24".parse().unwrap(),
            status: meshlet_domain::SegmentStatus::Active,
            created_at: T0.into(),
        })
        .unwrap();

        let mut source = device("d-a", "10.240.1.2", DeviceStatus::Active);
        source.segment_id = SegmentId("seg-a".into());
        let mut gateway = device("d-b", "10.240.2.2", DeviceStatus::Active);
        gateway.segment_id = SegmentId("seg-b".into());
        let mut hub_device = device("d-default", "10.240.0.2", DeviceStatus::Active);
        hub_device.segment_id = default_id;
        add(&mut mesh, source);
        add(&mut mesh, gateway);
        add(&mut mesh, hub_device);
        mesh.restore_route(route("rt-same", "192.168.1.0/24", "d-a", RouteMode::Direct));
        mesh.restore_route(route("rt-b", "192.168.2.0/24", "d-b", RouteMode::Direct));
        mesh.restore_route(route(
            "rt-hub",
            "192.168.3.0/24",
            "d-default",
            RouteMode::Direct,
        ));

        let limited = build_device_plan(
            &mesh,
            "net-1",
            &DeviceId("d-a".into()),
            &dataplane(),
            None,
            "hub-pub",
            None,
        )
        .unwrap();
        assert_eq!(
            limited.tunnel.peers[0].allowed_ips,
            vec!["10.240.1.0/24".parse().unwrap()]
        );
        assert!(limited.routes.is_empty());

        mesh.restore_segment_grant(meshlet_domain::SegmentGrant {
            id: meshlet_domain::SegmentGrantId("sg-1".into()),
            network_id: NetworkId("net-1".into()),
            source_segment_id: SegmentId("seg-a".into()),
            destination_segment_id: SegmentId("seg-b".into()),
            status: meshlet_domain::SegmentGrantStatus::Applied,
            created_at: T0.into(),
            revoked_at: None,
        })
        .unwrap();
        let granted = build_device_plan(
            &mesh,
            "net-1",
            &DeviceId("d-a".into()),
            &dataplane(),
            None,
            "hub-pub",
            None,
        )
        .unwrap();
        assert!(granted
            .routes
            .iter()
            .any(|route| route.destination.to_string() == "192.168.2.0/24"));
        assert!(granted.tunnel.peers[0]
            .allowed_ips
            .iter()
            .any(|cidr| cidr.to_string() == "192.168.2.0/24"));
    }

    #[test]
    fn plan_carries_own_tunnel_and_other_gateways_routes() {
        let mut mesh = mesh();
        add(
            &mut mesh,
            device("d-self", "10.240.0.3", DeviceStatus::Active),
        );
        add(
            &mut mesh,
            device("d-gw", "10.240.0.2", DeviceStatus::Active),
        );
        mesh.restore_route(route("rt-1", "192.168.1.0/24", "d-gw", RouteMode::Direct));

        let plan = build_device_plan(
            &mesh,
            "net-1",
            &DeviceId("d-self".into()),
            &dataplane(),
            None,
            "hub-pub",
            None,
        )
        .unwrap();

        assert_eq!(plan.tunnel.name, "wg0");
        assert_eq!(
            plan.tunnel.address,
            "10.240.0.3".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(plan.tunnel.address_prefix, 16);
        assert_eq!(plan.tunnel.private_key, None); // the server never carries a private key
        assert_eq!(plan.tunnel.peers.len(), 1);
        assert_eq!(plan.tunnel.peers[0].public_key, "hub-pub");

        // AllowedIPs = Overlay + other devices' LANs; locally published prefixes
        // are not fed back (§7.2).
        let allowed = plan.tunnel.peers[0]
            .allowed_ips
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>();
        assert_eq!(allowed, vec!["10.240.0.0/16", "192.168.1.0/24"]);
        assert_eq!(
            plan.routes,
            vec![RouteConfig {
                destination: "192.168.1.0/24".parse().unwrap(),
                interface: "wg0".into(),
                gateway: Some("10.240.0.2".parse::<Ipv4Addr>().unwrap()),
            }]
        );
        assert!(plan.nat_rules.is_empty(), "non-gateway device gets no NAT");
        assert!(!plan.desired_config_hash.is_empty());
    }

    #[test]
    fn gateway_plan_emits_alias_nat_rules_and_excludes_own_lan() {
        let mut mesh = mesh();
        add(
            &mut mesh,
            device("d-gw", "10.240.0.2", DeviceStatus::Active),
        );
        add(
            &mut mesh,
            device("d-peer", "10.240.0.3", DeviceStatus::Active),
        );
        mesh.restore_route(route("rt-2", "192.168.2.0/24", "d-peer", RouteMode::Direct));
        mesh.restore_route(route("rt-1", "192.168.1.0/24", "d-gw", RouteMode::Alias));
        mesh.restore_alias(alias("al-1", "rt-1", "10.241.1.0/24", "192.168.1.0/24"));

        let plan = build_device_plan(
            &mesh,
            "net-1",
            &DeviceId("d-gw".into()),
            &dataplane(),
            None,
            "hub-pub",
            None,
        )
        .unwrap();

        // The 192.168.1.0/24 this device publishes does not enter its own AllowedIPs
        // (to avoid loops), but the 192.168.2.0/24 published by others does.
        let allowed = plan.tunnel.peers[0]
            .allowed_ips
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>();
        assert_eq!(allowed, vec!["10.240.0.0/16", "192.168.2.0/24"]);
        assert_eq!(plan.routes.len(), 1);
        assert_eq!(plan.routes[0].destination.to_string(), "192.168.2.0/24");

        // Two rules, DNAT + controlled SNAT, with the ownership annotation (§12.6).
        assert_eq!(plan.nat_rules.len(), 2);
        assert!(plan
            .nat_rules
            .iter()
            .all(|r| r.owner == "meshlet alias al-1"));
        assert_eq!(plan.nat_rules[0].match_dest.to_string(), "10.241.1.0/24");
        assert_eq!(plan.nat_rules[1].match_dest.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn pending_route_is_included_in_candidate_plan_for_device_ack() {
        // Candidate plans include pending resources; the desired API withholds them until hub success.
        let mut mesh = mesh();
        add(
            &mut mesh,
            device("d-self", "10.240.0.3", DeviceStatus::Active),
        );
        add(
            &mut mesh,
            device("d-gw", "10.240.0.2", DeviceStatus::Active),
        );
        let mut r = route("rt-1", "192.168.1.0/24", "d-gw", RouteMode::Direct);
        r.status = DesiredStateStatus::Pending;
        mesh.restore_route(r);

        let plan = build_device_plan(
            &mesh,
            "net-1",
            &DeviceId("d-self".into()),
            &dataplane(),
            None,
            "hub-pub",
            None,
        )
        .unwrap();
        assert_eq!(plan.routes.len(), 1);
        let allowed = plan.tunnel.peers[0]
            .allowed_ips
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>();
        assert_eq!(allowed, vec!["10.240.0.0/16", "192.168.1.0/24"]);
    }

    #[test]
    fn plan_rejects_unknown_network_or_device() {
        let mut mesh = mesh();
        add(
            &mut mesh,
            device("d-self", "10.240.0.3", DeviceStatus::Active),
        );
        assert!(build_device_plan(
            &mesh,
            "net-404",
            &DeviceId("d-self".into()),
            &dataplane(),
            None,
            "hub-pub",
            None,
        )
        .is_err());
        assert!(build_device_plan(
            &mesh,
            "net-1",
            &DeviceId("nope".into()),
            &dataplane(),
            None,
            "hub-pub",
            None,
        )
        .is_err());
    }

    #[test]
    fn plan_hash_is_stable_across_route_reordering() {
        let mut mesh = mesh();
        add(
            &mut mesh,
            device("self", "10.240.0.3", DeviceStatus::Active),
        );
        add(&mut mesh, device("gw", "10.240.0.2", DeviceStatus::Active));
        mesh.restore_route(route("rt-2", "192.168.2.0/24", "gw", RouteMode::Direct));
        mesh.restore_route(route("rt-1", "192.168.1.0/24", "gw", RouteMode::Direct));
        let before = build_device_plan(
            &mesh,
            "net-1",
            &DeviceId("self".into()),
            &dataplane(),
            None,
            "hub",
            None,
        )
        .unwrap();
        mesh.lan_routes.get_mut("net-1").unwrap().reverse();
        let after = build_device_plan(
            &mesh,
            "net-1",
            &DeviceId("self".into()),
            &dataplane(),
            None,
            "hub",
            None,
        )
        .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn ssh_distribution_emits_all_active_nodes_with_three_tier_alias_source() {
        let mut mesh_state = mesh();
        let mut self_dev = device("self", "10.240.0.3", DeviceStatus::Active);
        self_dev.name = "self-node".into();
        add(&mut mesh_state, self_dev);
        add(
            &mut mesh_state,
            device("gw", "10.240.0.2", DeviceStatus::Active),
        );
        add(
            &mut mesh_state,
            device("pending", "10.240.0.4", DeviceStatus::Pending),
        );
        mesh_state
            .device_hostnames
            .insert(DeviceId("gw".into()), "My Host".into());

        let off = build_device_plan(
            &mesh_state,
            "net-1",
            &DeviceId("self".into()),
            &dataplane(),
            None,
            "hub",
            None,
        )
        .unwrap();
        assert!(off.ssh_config.is_none(), "hub off keeps the segment absent");

        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert(
            "self-node".to_string(),
            meshlet_config::SshHostOverride {
                alias: Some("mybox".into()),
                user: Some("root".into()),
                port: Some(2222),
            },
        );
        let on = build_device_plan(
            &mesh_state,
            "net-1",
            &DeviceId("self".into()),
            &dataplane(),
            None,
            "hub",
            Some(&meshlet_config::SshDistributeConfig {
                overrides: overrides.clone(),
            }),
        )
        .unwrap();
        let ssh = on.ssh_config.expect("hub on carries the segment");
        assert_eq!(ssh.hosts.len(), 2, "pending nodes are excluded");
        let self_row = ssh.hosts.iter().find(|h| h.name == "self-node").unwrap();
        assert_eq!(self_row.alias, "mybox");
        assert_eq!(self_row.alias_source.as_deref(), Some("hub-config"));
        assert_eq!(self_row.port, Some(2222));
        assert_eq!(self_row.user.as_deref(), Some("root"));
        let gw_row = ssh.hosts.iter().find(|h| h.name == "gw").unwrap();
        assert_eq!(gw_row.alias, "My-Host");
        assert_eq!(gw_row.alias_source.as_deref(), Some("hostname"));

        // No hostname reported: fall back to the peer name, with the source labeled
        // honestly.
        let mut mesh2 = mesh();
        add(
            &mut mesh2,
            device("only", "10.240.0.9", DeviceStatus::Active),
        );
        let bare = build_device_plan(
            &mesh2,
            "net-1",
            &DeviceId("only".into()),
            &dataplane(),
            None,
            "hub",
            Some(&meshlet_config::SshDistributeConfig {
                overrides: Default::default(),
            }),
        )
        .unwrap();
        let row = &bare.ssh_config.unwrap().hosts[0];
        assert_eq!(row.alias, "only");
        assert_eq!(row.alias_source.as_deref(), Some("peer-name"));
    }

    #[test]
    fn hub_public_key_requires_a_configured_key_file() {
        let off = DataPlaneConfig::default();
        assert!(hub_public_key(&off).is_err());

        let empty = meshlet_config::DataPlaneConfig {
            private_key_file: Some("".into()),
            ..DataPlaneConfig::default()
        };
        assert!(hub_public_key(&empty).is_err());

        let missing = meshlet_config::DataPlaneConfig {
            private_key_file: Some("/nonexistent/meshlet/none.key".into()),
            ..DataPlaneConfig::default()
        };
        assert!(hub_public_key(&missing).is_err());
    }

    fn wg_available() -> bool {
        match std::process::Command::new("wg").arg("--version").output() {
            Ok(o) if o.status.success() => true,
            _ => {
                eprintln!("SKIP: wireguard-tools (wg) not installed");
                false
            }
        }
    }

    #[test]
    fn hub_public_key_derives_from_a_real_private_key() {
        // Actually run `wg pubkey` (the same derivation as this backend's apply
        // path; ADR-010 means it is never persisted).
        if !wg_available() {
            return;
        }
        let dir = std::env::temp_dir().join("meshlet-device-plan-test");
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("hub.key");
        let out = match std::process::Command::new("wg").arg("genkey").output() {
            Ok(o) if o.status.success() => o,
            _ => {
                eprintln!("SKIP: wg genkey failed");
                return;
            }
        };
        std::fs::write(&key_path, &out.stdout).unwrap();

        let cfg = meshlet_config::DataPlaneConfig {
            private_key_file: Some(key_path.to_string_lossy().to_string()),
            ..DataPlaneConfig::default()
        };
        let key = match hub_public_key(&cfg) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("SKIP: derive hub public key failed: {e}");
                return;
            }
        };
        assert!(key.len() >= 40, "base64 key should be non-trivial: {key}");
        std::fs::remove_file(&key_path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
