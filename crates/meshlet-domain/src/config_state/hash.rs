//! 期望配置哈希（ADR-009 `desired_config_hash`）：对期望配置的确定性序列化
//! 取 SHA-256，作为「期望配置是否变化」的唯一判据。

use crate::cidr::Ipv4Cidr;
use crate::entities::{AliasMapping, Device, DeviceStatus, LanRoute};
use crate::segments::SegmentGrant;
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

/// 期望配置哈希（ADR-009 `desired_config_hash`）：对 overlay 网段、hub 地址、
/// 全部 **Active** 设备、全部 LAN 路由与全部 Alias 映射的确定性序列化取
/// SHA-256。顺序不敏感（设备按虚拟 IP、路由按目的网段、Alias 按前缀排序）；
/// `Pending`/`Revoked` 设备不入配置故不参与哈希；路由/Alias 删除即出哈希。
/// 标签随输入集演进（v2 = 加入路由行，v3 = 加入 Alias 行，v4 = 加入 Applied
/// Segment Grant 行），避免跨版本哈希误判相等。
pub fn desired_config_hash(
    overlay_cidr: &Ipv4Cidr,
    hub: Ipv4Addr,
    devices: &[Device],
    routes: &[LanRoute],
    aliases: &[AliasMapping],
    segment_grants: &[SegmentGrant],
) -> String {
    let mut lines = vec![
        "meshlet-desired-v4".to_string(),
        format!("overlay={overlay_cidr}"),
        format!("hub={hub}"),
    ];
    let mut active: Vec<&Device> = devices
        .iter()
        .filter(|d| d.status == DeviceStatus::Active)
        .collect();
    active.sort_by_key(|d| d.virtual_ipv4);
    for d in active {
        lines.push(format!(
            "device name={} vip={} pubkey={}",
            d.name, d.virtual_ipv4, d.public_key
        ));
    }
    let mut sorted_routes: Vec<&LanRoute> = routes.iter().collect();
    sorted_routes.sort_by(|a, b| (&a.destination_cidr, &a.id).cmp(&(&b.destination_cidr, &b.id)));
    for r in sorted_routes {
        lines.push(format!(
            "route dst={} gw={} mode={} return={}",
            r.destination_cidr,
            r.gateway_device_id,
            r.route_mode.as_str(),
            r.return_path_mode.as_str()
        ));
    }
    let mut sorted_aliases: Vec<&AliasMapping> = aliases.iter().collect();
    sorted_aliases.sort_by(|a, b| (&a.alias_cidr, &a.id).cmp(&(&b.alias_cidr, &b.id)));
    for a in sorted_aliases {
        lines.push(format!(
            "alias prefix={} target={} route={} mode={}",
            a.alias_cidr,
            a.target_cidr,
            a.lan_route_id,
            a.translation_mode.as_str()
        ));
    }
    let mut sorted_grants: Vec<&SegmentGrant> = segment_grants
        .iter()
        .filter(|g| g.status == crate::segments::SegmentGrantStatus::Applied)
        .collect();
    sorted_grants.sort_by(|a, b| {
        (&a.source_segment_id, &a.destination_segment_id, &a.id).cmp(&(
            &b.source_segment_id,
            &b.destination_segment_id,
            &b.id,
        ))
    });
    for g in sorted_grants {
        lines.push(format!(
            "segment-grant src={} dst={}",
            g.source_segment_id, g.destination_segment_id
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(lines.join("\n").as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::desired_config_hash;
    use crate::cidr::Ipv4Cidr;
    use crate::config_state::test_support::{net, T0, T1};
    use crate::entities::{
        AliasMapping, AliasMappingId, DesiredStateStatus, Device, DeviceId, DeviceStatus, LanRoute,
        LanRouteId, NetworkId, ReturnPathMode, RouteMode, TranslationMode,
    };
    use crate::segments::SegmentGrant;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    fn device(name: &str, ip: &str, status: DeviceStatus) -> Device {
        Device {
            id: crate::entities::DeviceId(name.into()),
            network_id: net("net-1"),
            name: name.into(),
            virtual_ipv4: ip.parse().unwrap(),
            public_key: format!("pub-{name}"),
            platform: crate::entities::Platform::Linux,
            status,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: T0.into(),
            approved_at: None,
            segment_id: crate::SegmentId("seg-net-1".into()),
            revoked_at: None,
            labels: BTreeMap::new(),
        }
    }

    fn grant(status: crate::segments::SegmentGrantStatus) -> SegmentGrant {
        SegmentGrant {
            id: crate::SegmentGrantId("sg-1".into()),
            network_id: net("net-1"),
            source_segment_id: crate::SegmentId("seg-src".into()),
            destination_segment_id: crate::SegmentId("seg-dst".into()),
            status,
            created_at: T0.into(),
            revoked_at: None,
        }
    }

    #[test]
    fn desired_config_hash_includes_only_applied_segment_grants() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let base = desired_config_hash(&overlay, hub, &[], &[], &[], &[]);

        let pending = grant(crate::segments::SegmentGrantStatus::Pending);
        let revoked = grant(crate::segments::SegmentGrantStatus::Revoked);
        assert_eq!(
            desired_config_hash(&overlay, hub, &[], &[], &[], &[pending]),
            base
        );
        assert_eq!(
            desired_config_hash(&overlay, hub, &[], &[], &[], &[revoked]),
            base
        );

        let mut applied = grant(crate::segments::SegmentGrantStatus::Applied);
        let with_applied =
            desired_config_hash(&overlay, hub, &[], &[], &[], std::slice::from_ref(&applied));
        assert_ne!(with_applied, base);

        let mut other = grant(crate::segments::SegmentGrantStatus::Applied);
        other.id = crate::SegmentGrantId("sg-2".into());
        assert_eq!(
            desired_config_hash(
                &overlay,
                hub,
                &[],
                &[],
                &[],
                &[applied.clone(), other.clone()]
            ),
            desired_config_hash(&overlay, hub, &[], &[], &[], &[other, applied.clone()])
        );

        applied.status = crate::segments::SegmentGrantStatus::Revoked;
        applied.revoked_at = Some(T1.into());
        assert_eq!(
            desired_config_hash(&overlay, hub, &[], &[], &[], &[applied]),
            base
        );
    }

    #[test]
    fn desired_config_hash_is_deterministic_and_device_order_insensitive() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let d1 = device("alpha", "10.240.0.2", DeviceStatus::Active);
        let d2 = device("beta", "10.240.0.3", DeviceStatus::Active);
        let h1 = desired_config_hash(&overlay, hub, &[d1.clone(), d2.clone()], &[], &[], &[]);
        let h2 = desired_config_hash(&overlay, hub, &[d2, d1], &[], &[], &[]);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn desired_config_hash_tracks_active_config_only() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let alpha = device("alpha", "10.240.0.2", DeviceStatus::Active);
        let base = desired_config_hash(&overlay, hub, std::slice::from_ref(&alpha), &[], &[], &[]);

        // 新设备加入 → 哈希变化。
        let beta = device("beta", "10.240.0.3", DeviceStatus::Active);
        assert_ne!(
            desired_config_hash(&overlay, hub, &[alpha.clone(), beta], &[], &[], &[],),
            base
        );

        // 改名 → 哈希变化（期望配置含设备名）。
        let mut renamed = alpha.clone();
        renamed.name = "alpha-2".into();
        assert_ne!(
            desired_config_hash(&overlay, hub, &[renamed], &[], &[], &[]),
            base
        );

        // 撤销（Revoked）→ 与无任何设备时一致（不入配置）。
        let mut revoked = alpha.clone();
        revoked.status = DeviceStatus::Revoked;
        assert_eq!(
            desired_config_hash(&overlay, hub, &[revoked], &[], &[], &[]),
            desired_config_hash(&overlay, hub, &[], &[], &[], &[])
        );

        // overlay 或 hub 变化 → 哈希变化。
        let other_overlay: Ipv4Cidr = "172.30.0.0/16".parse().unwrap();
        assert_ne!(
            desired_config_hash(
                &other_overlay,
                hub,
                std::slice::from_ref(&alpha),
                &[],
                &[],
                &[],
            ),
            base
        );
        let other_hub: Ipv4Addr = "10.240.0.254".parse().unwrap();
        assert_ne!(
            desired_config_hash(&overlay, other_hub, &[alpha], &[], &[], &[]),
            base
        );
    }

    fn route(dst: &str, gw: &str, mode: RouteMode) -> LanRoute {
        LanRoute {
            id: LanRouteId(format!("rt-{dst}-{gw}-{mode:?}")),
            network_id: NetworkId("net-1".into()),
            gateway_device_id: DeviceId(gw.into()),
            destination_cidr: dst.parse().unwrap(),
            route_mode: mode,
            return_path_mode: ReturnPathMode::DualRoute,
            status: DesiredStateStatus::Pending,
            created_at: T0.into(),
        }
    }

    fn alias(id: &str, alias_cidr: &str, target_cidr: &str, route_id: &str) -> AliasMapping {
        AliasMapping::new(
            AliasMappingId(id.into()),
            net("net-1"),
            LanRouteId(route_id.into()),
            alias_cidr.parse().unwrap(),
            target_cidr.parse().unwrap(),
            TranslationMode::DnatSnat,
        )
        .unwrap()
    }

    #[test]
    fn desired_config_hash_includes_routes_order_insensitively() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let a = route("192.168.1.0/24", "dev-1", RouteMode::Direct);
        let b = route("192.168.2.0/24", "dev-2", RouteMode::Alias);

        // 路由纳入期望配置。
        assert_ne!(
            desired_config_hash(&overlay, hub, &[], std::slice::from_ref(&a), &[], &[]),
            desired_config_hash(&overlay, hub, &[], &[], &[], &[])
        );
        // 顺序不敏感。
        assert_eq!(
            desired_config_hash(&overlay, hub, &[], &[a.clone(), b.clone()], &[], &[],),
            desired_config_hash(&overlay, hub, &[], &[b.clone(), a.clone()], &[], &[]),
        );
        // 返回路径模式 / 路由模式参与哈希。
        let mut snat = route("192.168.1.0/24", "dev-1", RouteMode::Direct);
        snat.return_path_mode = ReturnPathMode::ControlledSnat;
        assert_ne!(
            desired_config_hash(&overlay, hub, &[], std::slice::from_ref(&snat), &[], &[],),
            desired_config_hash(&overlay, hub, &[], std::slice::from_ref(&a), &[], &[],)
        );
        // 删除路由（不出现在输入里）→ 哈希不同于含路由时。
        let with_route = desired_config_hash(&overlay, hub, &[], &[a], &[], &[]);
        assert_ne!(
            with_route,
            desired_config_hash(&overlay, hub, &[], &[], &[], &[])
        );
    }

    #[test]
    fn desired_config_hash_includes_aliases_order_insensitively() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let a1 = alias("al-1", "10.241.1.0/24", "192.168.1.0/24", "rt-1");
        let a2 = alias("al-2", "10.241.2.0/24", "192.168.2.0/24", "rt-2");

        // Alias 纳入期望配置。
        let base = desired_config_hash(&overlay, hub, &[], &[], &[], &[]);
        assert_ne!(
            desired_config_hash(&overlay, hub, &[], &[], std::slice::from_ref(&a1), &[]),
            base
        );
        // 顺序不敏感。
        assert_eq!(
            desired_config_hash(&overlay, hub, &[], &[], &[a1.clone(), a2.clone()], &[],),
            desired_config_hash(&overlay, hub, &[], &[], &[a2.clone(), a1.clone()], &[])
        );
        // 前缀或绑定路由变化 → 哈希变化。
        let other = alias("al-1", "10.241.9.0/24", "192.168.9.0/24", "rt-1");
        assert_ne!(
            desired_config_hash(&overlay, hub, &[], &[], std::slice::from_ref(&other), &[],),
            desired_config_hash(&overlay, hub, &[], &[], std::slice::from_ref(&a1), &[],)
        );
        // 删除 Alias → 哈希回到 base。
        assert_eq!(desired_config_hash(&overlay, hub, &[], &[], &[], &[]), base);
    }
}
