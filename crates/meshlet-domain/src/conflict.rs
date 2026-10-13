//! CIDR 冲突检测（[存档 §6.2–§6.3](../../docs/review/chatgpt-2026-10-13.md)、ADR-004）。
//!
//! 六项检查 + 三类分级：
//! - `ServerKnown`：服务端已知冲突 → 阻断；
//! - `ClientLocal`：Agent 上报的客户端本地冲突 → 阻断或告警（由调用方决定）；
//! - `Unverifiable`：无法确认（客户端报告缺失）→ **仅警告，不宣称网络可用**。

use crate::cidr::Ipv4Cidr;
use crate::entities::{AliasMapping, LanRoute};

/// 冲突认知来源（§6.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    ServerKnown,
    ClientLocal,
    Unverifiable,
}

impl ConflictKind {
    /// 阻断性冲突（Unverifiable 仅警告）。
    pub fn is_blocking(&self) -> bool {
        !matches!(self, ConflictKind::Unverifiable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictCode {
    OverlayAliasOverlap,
    OverlayExistingRouteOverlap,
    AliasAliasOverlap,
    LanRouteConflict,
    AliasTargetMismatch,
    ClientRouteOverlap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub code: ConflictCode,
    pub kind: ConflictKind,
    pub detail: String,
}

impl Conflict {
    /// 阻断性冲突（`Unverifiable` 仅警告，§6.3）。
    pub fn is_blocking(&self) -> bool {
        self.kind.is_blocking()
    }
}

/// 已有路由的观察位置（服务端 vs 客户端本地）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSource {
    Server,
    Client,
}

/// 检查 1：Overlay CIDR 与任一 Alias CIDR 重叠。
pub fn overlay_alias_overlap(overlay: Ipv4Cidr, aliases: &[AliasMapping]) -> Vec<Conflict> {
    aliases
        .iter()
        .filter(|a| a.alias_cidr.overlaps(&overlay))
        .map(|a| Conflict {
            code: ConflictCode::OverlayAliasOverlap,
            kind: ConflictKind::ServerKnown,
            detail: format!("alias {} overlaps overlay {}", a.alias_cidr, overlay),
        })
        .collect()
}

/// 检查 2 + 6：候选网段与已有路由冲突。
/// - 服务端已有路由 → `ServerKnown`；
/// - 客户端本地路由 → `ClientLocal`；
/// - `client_routes = None`（客户端未上报）→ 生成一条 `Unverifiable` 警告。
pub fn against_existing_routes(
    candidate: Ipv4Cidr,
    server_routes: &[Ipv4Cidr],
    client_routes: Option<&[Ipv4Cidr]>,
) -> Vec<Conflict> {
    let mut out = Vec::new();
    for r in server_routes {
        if r.overlaps(&candidate) {
            out.push(Conflict {
                code: ConflictCode::OverlayExistingRouteOverlap,
                kind: ConflictKind::ServerKnown,
                detail: format!("candidate {candidate} overlaps server route {r}"),
            });
        }
    }
    match client_routes {
        Some(routes) => {
            for r in routes {
                if r.overlaps(&candidate) {
                    out.push(Conflict {
                        code: ConflictCode::ClientRouteOverlap,
                        kind: ConflictKind::ClientLocal,
                        detail: format!("candidate {candidate} overlaps client local route {r}"),
                    });
                }
            }
        }
        None => out.push(Conflict {
            code: ConflictCode::ClientRouteOverlap,
            kind: ConflictKind::Unverifiable,
            detail: format!(
                "client local routes unknown for candidate {candidate}; \
                 cannot confirm the network is usable"
            ),
        }),
    }
    out
}

/// 检查 3：Alias 之间的重叠。
pub fn alias_alias_overlap(aliases: &[AliasMapping]) -> Vec<Conflict> {
    let mut out = Vec::new();
    for i in 0..aliases.len() {
        for j in (i + 1)..aliases.len() {
            if aliases[i].alias_cidr.overlaps(&aliases[j].alias_cidr) {
                out.push(Conflict {
                    code: ConflictCode::AliasAliasOverlap,
                    kind: ConflictKind::ServerKnown,
                    detail: format!(
                        "alias {} overlaps alias {}",
                        aliases[i].alias_cidr, aliases[j].alias_cidr
                    ),
                });
            }
        }
    }
    out
}

/// 检查 4：同一网络内 LAN Route 冲突（目标重叠即冲突——同一目的地不能有两个并行转发者）。
pub fn lan_route_conflicts(routes: &[LanRoute]) -> Vec<Conflict> {
    let mut out = Vec::new();
    for i in 0..routes.len() {
        for j in (i + 1)..routes.len() {
            let (a, b) = (&routes[i], &routes[j]);
            if a.destination_cidr.overlaps(&b.destination_cidr) {
                out.push(Conflict {
                    code: ConflictCode::LanRouteConflict,
                    kind: ConflictKind::ServerKnown,
                    detail: format!(
                        "route {} via {} overlaps route {} via {}",
                        a.destination_cidr, a.gateway_device_id, b.destination_cidr, b.gateway_device_id
                    ),
                });
            }
        }
    }
    out
}

/// 检查 5：Alias 的 Target 与所绑定 LAN Route 不一致（第一版要求完全一致）。
pub fn alias_target_mismatch(alias: &AliasMapping, bound_route: &LanRoute) -> Vec<Conflict> {
    if alias.target_cidr == bound_route.destination_cidr {
        Vec::new()
    } else {
        vec![Conflict {
            code: ConflictCode::AliasTargetMismatch,
            kind: ConflictKind::ServerKnown,
            detail: format!(
                "alias target {} != bound lan route destination {}",
                alias.target_cidr, bound_route.destination_cidr
            ),
        }]
    }
}

/// §6.2 六项的聚合入口（客户端路由由调用方单独传入）。
pub fn check_network(
    overlay: Ipv4Cidr,
    aliases: &[AliasMapping],
    routes: &[LanRoute],
    server_routes: &[Ipv4Cidr],
    client_routes: Option<&[Ipv4Cidr]>,
) -> Vec<Conflict> {
    let mut out = Vec::new();
    out.extend(overlay_alias_overlap(overlay, aliases));
    out.extend(against_existing_routes(overlay, server_routes, client_routes));
    out.extend(alias_alias_overlap(aliases));
    out.extend(lan_route_conflicts(routes));
    for alias in aliases {
        if let Some(route) = routes.iter().find(|r| r.id == alias.lan_route_id) {
            out.extend(alias_target_mismatch(alias, route));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{
        AliasMappingId, DesiredStateStatus, LanRouteId, NetworkId, DeviceId, ReturnPathMode,
        RouteMode, TranslationMode,
    };

    fn alias(id: &str, alias_cidr: &str, target_cidr: &str) -> AliasMapping {
        AliasMapping::new(
            AliasMappingId(id.into()),
            NetworkId("net-1".into()),
            LanRouteId("r-1".into()),
            alias_cidr.parse().unwrap(),
            target_cidr.parse().unwrap(),
            TranslationMode::DnatSnat,
        )
        .unwrap()
    }

    fn route(id: &str, dest: &str, gw: &str) -> LanRoute {
        LanRoute {
            id: LanRouteId(id.into()),
            network_id: NetworkId("net-1".into()),
            gateway_device_id: DeviceId(gw.into()),
            destination_cidr: dest.parse().unwrap(),
            route_mode: RouteMode::Alias,
            return_path_mode: ReturnPathMode::ControlledSnat,
            status: DesiredStateStatus::Applied,
            created_at: "2026-10-14T08:00:00Z".into(),
        }
    }

    #[test]
    fn overlay_alias_overlap_detected_and_clean() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let bad = alias("a-1", "10.240.5.0/24", "192.168.5.0/24");
        let good = alias("a-2", "10.241.1.0/24", "192.168.1.0/24");
        let out = overlay_alias_overlap(overlay, &[bad, good.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, ConflictCode::OverlayAliasOverlap);
        assert_eq!(out[0].kind, ConflictKind::ServerKnown);
        assert!(out[0].is_blocking());
        assert!(overlay_alias_overlap(overlay, &[good]).is_empty());
    }

    #[test]
    fn existing_route_conflict_classified_by_source() {
        let candidate: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let server: Vec<Ipv4Cidr> = vec!["10.240.1.0/24".parse().unwrap()];
        let client: Vec<Ipv4Cidr> = vec!["10.240.2.0/24".parse().unwrap()];

        let out = against_existing_routes(candidate, &server, Some(&client));
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|c| c.kind == ConflictKind::ServerKnown));
        assert!(out.iter().any(|c| c.kind == ConflictKind::ClientLocal));

        // 客户端未上报：一条 Unverifiable 警告，非阻断。
        let out = against_existing_routes(candidate, &server, None);
        assert_eq!(out.len(), 2);
        let unver = out.iter().find(|c| c.kind == ConflictKind::Unverifiable).unwrap();
        assert!(!unver.is_blocking());
        assert!(unver.detail.contains("cannot confirm"));

        // 双侧都干净 + 客户端已上报 → 空。
        assert!(against_existing_routes(candidate, &[], Some(&[])).is_empty());
    }

    #[test]
    fn alias_alias_overlap_pairwise() {
        let a1 = alias("a-1", "10.241.1.0/24", "192.168.1.0/24");
        let a2 = alias("a-2", "10.241.1.128/25", "192.168.2.128/25"); // 与 a-1 重叠
        let a3 = alias("a-3", "10.242.1.0/24", "192.168.3.0/24");
        let out = alias_alias_overlap(&[a1.clone(), a2, a3.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, ConflictCode::AliasAliasOverlap);
        assert!(alias_alias_overlap(&[a1, a3]).is_empty());
    }

    #[test]
    fn lan_route_conflict_on_overlapping_destinations() {
        let r1 = route("r-1", "192.168.10.0/24", "gw-home");
        let r2 = route("r-2", "192.168.10.128/25", "gw-office"); // 重叠目的地
        let r3 = route("r-3", "192.168.20.0/24", "gw-home");
        let out = lan_route_conflicts(&[r1.clone(), r2, r3.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, ConflictCode::LanRouteConflict);
        // 同一网关发布不同网段不冲突。
        assert!(lan_route_conflicts(&[r1, r3]).is_empty());
    }

    #[test]
    fn alias_target_must_match_bound_route() {
        let a = alias("a-1", "10.241.1.0/24", "192.168.1.0/24");
        let bound = route("r-1", "192.168.1.0/24", "gw-home");
        assert!(alias_target_mismatch(&a, &bound).is_empty());

        let other = route("r-9", "192.168.9.0/24", "gw-home");
        let out = alias_target_mismatch(&a, &other);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, ConflictCode::AliasTargetMismatch);
    }

    #[test]
    fn aggregate_check_network_reports_all_categories() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let a_bad = alias("a-1", "10.240.9.0/24", "192.168.1.0/24"); // 与 overlay 重叠
        let a_ok = alias("a-2", "10.241.1.0/24", "192.168.1.0/24");
        let r1 = route("r-1", "192.168.1.0/24", "gw-home");
        let r2 = route("r-2", "192.168.1.64/26", "gw-office"); // 与 r-1 重叠

        let out = check_network(
            overlay,
            &[a_bad.clone(), a_ok.clone()],
            &[r1.clone(), r2],
            &["10.240.16.0/20".parse().unwrap()], // 服务端已有路由与 overlay 重叠
            None,                                // 客户端未上报
        );
        let codes: Vec<_> = out.iter().map(|c| c.code).collect();
        assert!(codes.contains(&ConflictCode::OverlayAliasOverlap));
        assert!(codes.contains(&ConflictCode::OverlayExistingRouteOverlap));
        assert!(codes.contains(&ConflictCode::LanRouteConflict));
        assert!(codes.contains(&ConflictCode::ClientRouteOverlap)); // Unverifiable 警告
        // 无一 ClientLocal（客户端未上报数据），且存在非阻断项。
        assert!(out.iter().all(|c| c.kind != ConflictKind::ClientLocal));
        assert!(out.iter().any(|c| !c.is_blocking()));
        // 清洁场景：服务端无冲突、客户端已上报且干净 → 无任何冲突。
        let clean = check_network(
            "10.240.0.0/16".parse().unwrap(),
            &[a_ok],
            &[r1],
            &[],
            Some(&[]),
        );
        assert!(clean.is_empty(), "unexpected: {clean:?}");
    }
}
