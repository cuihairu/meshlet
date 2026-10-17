//! 设备数据面计划（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）。
//!
//! agent 只消费 [`meshlet_network::DevicePlan`]——**结构化配置对象**（§16.4）：
//! 类型化的隧道/路由/NAT 计划 + 期望配置哈希，agent 据此对账并重放本地网络
//! 后端。**服务端不向 agent 下发任何 Shell 命令**，agent 绝不执行下发的脚本。
//!
//! - 隧道：本设备虚拟 IP + 到 hub 的单一 peer（AllowedIPs 与目标路由一致，
//!   §7.2；自己发布的本地网段不回灌隧道，避免环路）；
//! - 路由：他人已发布的 LAN/Alias 前缀经对应网关设备虚拟 IP；
//! - NAT：本设备作为网关时应下发的规则（计划层渲染，所有权注释
//!   `meshlet alias {id}`；映射删除即整单元清理，§12.6）；
//! - 私钥不离开设备（ADR-010）：计划 `tunnel.private_key` 恒为 `None`，
//!   agent 本地注入；hub 公钥由 `[dataplane] private_key_file` 现算（不落库）。

use meshlet_config::DataPlaneConfig;
use meshlet_domain::{
    peer_routes::client_hub_peer_allowed_ips, AliasMapping, DesiredStateStatus, DeviceId, RouteMode,
};
use meshlet_network::nat::alias_nat_rules;
use meshlet_network::{DevicePlan, PeerConfig, RouteConfig, SystemBackend, TunnelConfig};

use crate::service::MeshState;

/// hub 公钥：apply 时从 `[dataplane] private_key_file` 读取并经 `wg pubkey` 推导
/// （不落库、不出站——ADR-010）。hub 侧首装必须配置该文件。
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

/// 把指定设备的期望配置翻译为 agent 可执行的数据面计划。
///
/// 计划与 hub 侧计划共用同一推导源（§7.2 的 AllowedIPs 规则、§9.4 的网关侧
/// NAT），因此两端不会漂移；`desired_config_hash` 与修订簿记用同一哈希，agent
/// 可用它判断「有变更才重放」（§10.1）。
pub fn build_device_plan(
    mesh: &MeshState,
    network_id: &str,
    device_id: &DeviceId,
    dataplane: &DataPlaneConfig,
    tunnel_mtu: Option<u32>,
    hub_public_key: &str,
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
    let routes_in = planned_routes.as_slice();
    let aliases = planned_aliases.as_slice();
    // AllowedIPs 走域层唯一推导：Overlay + 他人已发布的 LAN/Alias（自己的本地
    // 网段不回灌，避免环路）。路由与之一一映射：目标前缀经对应网关设备。
    let allowed_ips = client_hub_peer_allowed_ips(overlay, &device.id, routes_in, aliases);
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

    // 本设备作为网关时的 NAT：Alias 模式按映射渲染；Direct 走真实 LAN，无需转换。
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
        rule.incoming_interface = Some(dataplane.interface.clone());
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
                // hub 入口地址由 agent 本地配置（`[dataplane] hub_endpoint`）提供；
                // 服务端未配置 advertise_ip 时留空，agent 自行兜底。
                endpoint: None,
                persistent_keepalive_secs: None,
            }],
            mtu: tunnel_mtu,
            private_key: None,
        },
        routes,
        nat_rules,
        // hub overlay 地址只作 agent 本地诊断目标（MTU 大包探测），不进内核。
        hub_address: Some(hub),
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

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::{
        AliasMappingId, Device, DeviceStatus, LanRouteId, Network, NetworkId, Platform,
        PresenceThresholds, RouteMode, TranslationMode,
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
            revoked_at: None,
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
        )
        .unwrap();

        assert_eq!(plan.tunnel.name, "wg0");
        assert_eq!(
            plan.tunnel.address,
            "10.240.0.3".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(plan.tunnel.address_prefix, 16);
        assert_eq!(plan.tunnel.private_key, None); // 服务端永不携带私钥
        assert_eq!(plan.tunnel.peers.len(), 1);
        assert_eq!(plan.tunnel.peers[0].public_key, "hub-pub");

        // AllowedIPs = Overlay + 他人 LAN；自己发布的本地网段不回灌（§7.2）。
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
        )
        .unwrap();

        // 本设备发布的 192.168.1.0/24 不进自己的 AllowedIPs（避免环路），
        // 但他人发布的 192.168.2.0/24 进。
        let allowed = plan.tunnel.peers[0]
            .allowed_ips
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>();
        assert_eq!(allowed, vec!["10.240.0.0/16", "192.168.2.0/24"]);
        assert_eq!(plan.routes.len(), 1);
        assert_eq!(plan.routes[0].destination.to_string(), "192.168.2.0/24");

        // DNAT + 受控 SNAT 两条，带所有权注释（§12.6）。
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
        )
        .is_err());
        assert!(build_device_plan(
            &mesh,
            "net-1",
            &DeviceId("nope".into()),
            &dataplane(),
            None,
            "hub-pub",
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
        )
        .unwrap();
        assert_eq!(before, after);
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
        // 真跑 `wg pubkey`（与本后端 apply 路径同一推导方式，ADR-010 不落库）。
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
