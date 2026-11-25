//! CIDR conflict detection ([archive §6.2–§6.3](../../docs/review/chatgpt-2026-10-13.md), ADR-004).
//!
//! Six checks + three severity classes:
//! - `ServerKnown`: conflict already known to the server → blocking;
//! - `ClientLocal`: client-local conflict reported by the agent → blocking or warning (caller decides);
//! - `Unverifiable`: cannot be confirmed (client report missing) → **warning only, do not claim the network is usable**.

use crate::cidr::Ipv4Cidr;
use crate::entities::{AliasMapping, LanRoute, RouteMode};
use crate::segments::Segment;

/// Where the conflict knowledge comes from (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConflictKind {
    ServerKnown,
    ClientLocal,
    Unverifiable,
}

impl ConflictKind {
    /// Blocking conflicts (Unverifiable is warning-only).
    pub fn is_blocking(&self) -> bool {
        !matches!(self, ConflictKind::Unverifiable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConflictCode {
    OverlayAliasOverlap,
    OverlayExistingRouteOverlap,
    AliasAliasOverlap,
    LanRouteConflict,
    AliasTargetMismatch,
    ClientRouteOverlap,
    SegmentSegmentOverlap,
    SegmentAliasOverlap,
    SegmentOutsideOverlay,
    AmbiguousInput,
    DuplicateDeviceAddress,
    ForeignObject,
    UnknownGateway,
    UnknownSegmentGrantEndpoint,
    OrphanAliasMapping,
    AliasRouteAmbiguous,
    DeviceOutsideSegment,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Conflict {
    pub code: ConflictCode,
    pub kind: ConflictKind,
    pub detail: String,
}

impl Conflict {
    /// Blocking conflicts (`Unverifiable` is warning-only, §6.3).
    pub fn is_blocking(&self) -> bool {
        self.kind.is_blocking()
    }
}

/// Where an existing route was observed (server-side vs client-local).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSource {
    Server,
    Client,
}

/// Check 1: the overlay CIDR overlaps an alias CIDR.
pub fn segment_segment_overlap(segments: &[Segment]) -> Vec<Conflict> {
    let mut out = Vec::new();
    for i in 0..segments.len() {
        for j in (i + 1)..segments.len() {
            if segments[i].cidr.overlaps(&segments[j].cidr) {
                out.push(Conflict {
                    code: ConflictCode::SegmentSegmentOverlap,
                    kind: ConflictKind::ServerKnown,
                    detail: format!(
                        "segment {} overlaps segment {}",
                        segments[i].cidr, segments[j].cidr
                    ),
                });
            }
        }
    }
    out
}

/// Segment prefixes share the tunnel-visible forwarding namespace with aliases.
pub fn segment_alias_overlap(segments: &[Segment], aliases: &[AliasMapping]) -> Vec<Conflict> {
    segments
        .iter()
        .flat_map(|segment| {
            aliases
                .iter()
                .filter(|alias| segment.cidr.overlaps(&alias.alias_cidr))
                .map(move |alias| Conflict {
                    code: ConflictCode::SegmentAliasOverlap,
                    kind: ConflictKind::ServerKnown,
                    detail: format!(
                        "segment {} overlaps alias {}",
                        segment.cidr, alias.alias_cidr
                    ),
                })
        })
        .collect()
}

/// Strict overlay containment; default and child segments must remain inside
/// the overlay so child trust boundaries cannot escape their address space.
pub fn segment_overlay_containment(overlay: Ipv4Cidr, segments: &[Segment]) -> Vec<Conflict> {
    segments
        .iter()
        .filter(|segment| !overlay.contains_cidr(&segment.cidr))
        .map(|segment| Conflict {
            code: ConflictCode::SegmentOutsideOverlay,
            kind: ConflictKind::ServerKnown,
            detail: format!(
                "segment {} must be contained by overlay {overlay}",
                segment.cidr
            ),
        })
        .collect()
}

/// Check 1: the overlay CIDR overlaps an alias CIDR.
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

/// Checks 2 + 6: the candidate subnet conflicts with existing routes.
/// - existing server route → `ServerKnown`;
/// - client-local route → `ClientLocal`;
/// - `client_routes = None` (client did not report) → emit one `Unverifiable` warning.
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

/// Check 3: overlaps between aliases.
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

/// Check 4: LAN route conflicts within one network (overlapping destinations conflict — one destination cannot have two parallel forwarders).
///
/// Exception (ADR-006 flagship scenario): two **Alias-mode** routes may have overlapping real LAN prefixes —
/// two sites each have a `192.168.1.0/24`, reachable simultaneously via their own distinct alias prefixes. The
/// forwarding prefix visible externally is the alias (uniqueness enforced by `alias_alias_overlap`); the real prefix
/// never enters any tunnel's AllowedIPs, so the kernel has no parallel forwarders. Direct routes
/// still conflict with any overlapping destination (a directly connected real prefix has only one forwarder).
pub fn lan_route_conflicts(routes: &[LanRoute]) -> Vec<Conflict> {
    let mut out = Vec::new();
    for i in 0..routes.len() {
        for j in (i + 1)..routes.len() {
            let (a, b) = (&routes[i], &routes[j]);
            if a.destination_cidr.overlaps(&b.destination_cidr)
                && !(a.route_mode == RouteMode::Alias
                    && b.route_mode == RouteMode::Alias
                    && a.gateway_device_id != b.gateway_device_id)
            {
                out.push(Conflict {
                    code: ConflictCode::LanRouteConflict,
                    kind: ConflictKind::ServerKnown,
                    detail: format!(
                        "route {} via {} overlaps route {} via {}",
                        a.destination_cidr,
                        a.gateway_device_id,
                        b.destination_cidr,
                        b.gateway_device_id
                    ),
                });
            }
        }
    }
    out
}

/// Check 5: the alias target does not match its bound LAN route (v1 requires an exact match).
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

/// Aggregate entry point for the six §6.2 checks (client routes are passed in separately by the caller).
pub fn check_network(
    overlay: Ipv4Cidr,
    aliases: &[AliasMapping],
    routes: &[LanRoute],
    segments: &[Segment],
    server_routes: &[Ipv4Cidr],
    client_routes: Option<&[Ipv4Cidr]>,
) -> Vec<Conflict> {
    let mut out = Vec::new();
    out.extend(overlay_alias_overlap(overlay, aliases));
    out.extend(against_existing_routes(
        overlay,
        server_routes,
        client_routes,
    ));
    out.extend(alias_alias_overlap(aliases));
    out.extend(lan_route_conflicts(routes));
    out.extend(segment_segment_overlap(segments));
    out.extend(segment_alias_overlap(segments, aliases));
    out.extend(segment_overlay_containment(overlay, segments));
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
        AliasMappingId, DesiredStateStatus, DeviceId, LanRouteId, NetworkId, ReturnPathMode,
        RouteMode, SegmentId, TranslationMode,
    };
    use crate::segments::SegmentStatus;

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
            route_mode: RouteMode::Direct,
            return_path_mode: ReturnPathMode::ControlledSnat,
            status: DesiredStateStatus::Applied,
            created_at: "2026-10-14T08:00:00Z".into(),
        }
    }

    fn segment(id: &str, name: &str, cidr: &str) -> Segment {
        Segment {
            id: SegmentId(id.into()),
            network_id: NetworkId("net-1".into()),
            name: name.into(),
            cidr: cidr.parse().unwrap(),
            status: SegmentStatus::Active,
            created_at: "2026-10-17T00:00:00Z".into(),
        }
    }

    #[test]
    fn segment_containment_conflict_covers_parent_and_child_rules() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let out = segment_overlay_containment(
            overlay,
            &[
                segment("seg-parent", "users", "10.240.0.0/14"),
                segment("seg-partial", "guests", "10.241.0.0/24"),
                segment("seg-default-child", "default", "10.240.0.0/24"),
                segment("seg-user", "servers", "10.240.255.0/24"),
                segment("seg-default", "default", "10.240.0.0/16"),
            ],
        );
        let details: Vec<_> = out
            .iter()
            .map(|conflict| conflict.detail.as_str())
            .collect();
        assert_eq!(details.len(), 2);
        assert!(details.iter().all(|detail| detail.contains("contained by")));
        assert!(!details.iter().any(|detail| detail.contains("seg-user")));
    }

    #[test]
    fn segment_conflicts_detect_pairwise_alias_and_clean_containment() {
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        let users = segment("seg-users", "users", "10.240.1.0/24");
        let users_child = segment("seg-users-child", "users-child", "10.240.1.128/25");
        let other = segment("seg-other", "other", "10.240.2.0/24");

        let out = segment_segment_overlap(&[users.clone(), users_child.clone(), other.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, ConflictCode::SegmentSegmentOverlap);
        assert_eq!(out[0].kind, ConflictKind::ServerKnown);
        assert!(out[0].is_blocking());
        assert!(segment_segment_overlap(&[users.clone(), other.clone()]).is_empty());

        let mapped_alias = alias("a-1", "10.241.1.0/24", "192.168.1.0/24");
        let conflicting_alias = alias("a-2", "10.240.2.0/25", "192.168.2.0/25");
        let out = segment_alias_overlap(
            &[users.clone(), other.clone()],
            &[mapped_alias.clone(), conflicting_alias],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, ConflictCode::SegmentAliasOverlap);
        assert_eq!(out[0].kind, ConflictKind::ServerKnown);
        assert!(segment_alias_overlap(&[users, other], &[mapped_alias]).is_empty());

        let default = segment("seg-default", "default", "10.240.0.0/16");
        let child = segment("seg-child", "servers", "10.240.3.0/24");
        assert!(segment_overlay_containment(overlay, &[default, child]).is_empty());
    }

    fn alias_route(id: &str, dest: &str, gw: &str) -> LanRoute {
        LanRoute {
            route_mode: RouteMode::Alias,
            ..route(id, dest, gw)
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

        // Client did not report: one Unverifiable warning, non-blocking.
        let out = against_existing_routes(candidate, &server, None);
        assert_eq!(out.len(), 2);
        let unver = out
            .iter()
            .find(|c| c.kind == ConflictKind::Unverifiable)
            .unwrap();
        assert!(!unver.is_blocking());
        assert!(unver.detail.contains("cannot confirm"));

        // Both sides clean + client reported → empty.
        assert!(against_existing_routes(candidate, &[], Some(&[])).is_empty());
    }

    #[test]
    fn alias_alias_overlap_pairwise() {
        let a1 = alias("a-1", "10.241.1.0/24", "192.168.1.0/24");
        let a2 = alias("a-2", "10.241.1.128/25", "192.168.2.128/25"); // overlaps a-1
        let a3 = alias("a-3", "10.242.1.0/24", "192.168.3.0/24");
        let out = alias_alias_overlap(&[a1.clone(), a2, a3.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, ConflictCode::AliasAliasOverlap);
        assert!(alias_alias_overlap(&[a1, a3]).is_empty());
    }

    #[test]
    fn lan_route_conflict_on_overlapping_destinations() {
        let r1 = route("r-1", "192.168.10.0/24", "gw-home");
        let r2 = route("r-2", "192.168.10.128/25", "gw-office"); // overlapping destination
        let r3 = route("r-3", "192.168.20.0/24", "gw-home");
        let out = lan_route_conflicts(&[r1.clone(), r2, r3.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, ConflictCode::LanRouteConflict);
        // Different subnets advertised by the same gateway do not conflict.
        assert!(lan_route_conflicts(&[r1, r3]).is_empty());
    }

    #[test]
    fn dual_alias_routes_with_the_same_lan_do_not_conflict() {
        // ADR-006 flagship scenario: two sites each have a 192.168.1.0/24, both reachable
        // via different aliases — real prefix overlap is not a conflict; the visible forwarding prefixes are the aliases.
        let s1 = alias_route("r-1", "192.168.1.0/24", "gw-site1");
        let s2 = alias_route("r-2", "192.168.1.0/24", "gw-site2");
        assert!(
            lan_route_conflicts(&[s1, s2]).is_empty(),
            "dual alias sites with the same real lan must coexist"
        );

        // But a Direct prefix overlapping an alias's real prefix is still a conflict: a directly connected real prefix has one forwarder.
        let direct = route("r-3", "192.168.1.0/24", "gw-office");
        let alias_one = alias_route("r-4", "192.168.1.0/24", "gw-home");
        let out = lan_route_conflicts(&[direct, alias_one]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, ConflictCode::LanRouteConflict);
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
        let a_bad = alias("a-1", "10.240.9.0/24", "192.168.1.0/24"); // overlaps the overlay
        let a_ok = alias("a-2", "10.241.1.0/24", "192.168.9.0/24");
        let r1 = route("r-1", "192.168.1.0/24", "gw-home");
        let r2 = route("r-2", "192.168.1.64/26", "gw-office"); // overlaps r-1
        let parent = segment("seg-parent", "users", "10.240.0.0/14");
        let parent_child = segment("seg-parent-child", "guests", "10.240.1.0/24");
        let clean_child = segment("seg-clean-child", "servers", "10.240.2.0/24");

        let out = check_network(
            overlay,
            &[a_bad.clone(), a_ok.clone()],
            &[r1.clone(), r2],
            &[parent, parent_child, clean_child],
            &["10.240.16.0/20".parse().unwrap()], // an existing server route overlaps the overlay
            None,                                 // client did not report
        );
        let codes: Vec<_> = out.iter().map(|c| c.code).collect();
        assert!(codes.contains(&ConflictCode::OverlayAliasOverlap));
        assert!(codes.contains(&ConflictCode::OverlayExistingRouteOverlap));
        assert!(codes.contains(&ConflictCode::LanRouteConflict));
        assert!(codes.contains(&ConflictCode::ClientRouteOverlap)); // Unverifiable warning
                                                                    // no ClientLocal (client reported no data), and a non-blocking item is present.
        assert!(out.iter().all(|c| c.kind != ConflictKind::ClientLocal));
        assert!(out.iter().any(|c| !c.is_blocking()));
        assert!(codes.contains(&ConflictCode::SegmentOutsideOverlay));
        assert!(codes.contains(&ConflictCode::SegmentAliasOverlap));
        assert!(codes.contains(&ConflictCode::SegmentSegmentOverlap));
        assert!(codes.contains(&ConflictCode::AliasTargetMismatch));
        // Clean scenario: no server conflicts, client reported and clean → no conflicts at all.
        let clean = check_network(
            "10.240.0.0/16".parse().unwrap(),
            &[{
                let mut valid_alias = a_ok.clone();
                valid_alias.target_cidr = "192.168.1.0/24".parse().unwrap();
                valid_alias
            }],
            &[r1],
            &[],
            &[],
            Some(&[]),
        );
        assert!(clean.is_empty(), "unexpected: {clean:?}");
    }
}
